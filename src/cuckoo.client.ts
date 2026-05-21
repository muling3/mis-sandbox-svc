// Cuckoo REST integration with an in-process mock fallback.
//
// When CUCKOO_URL is set, talks to a real Cuckoo container via its REST
// API:
//   POST /tasks/create/file
//   GET  /tasks/view/<id>     (polled until status=reported|completed)
//   GET  /tasks/report/<id>
// When CUCKOO_URL is unset, returns a deterministic synthetic report:
// EICAR substring → score 9.2 with an eicar_signature hit; otherwise
// score 0 (clean). The Kafka event surface is identical either way
// (workflow doc §6.2).

import { Injectable, Logger } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { loadConfig } from './config';
import type { CuckooReport, Submission } from './types';

const EICAR_MARKER = 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE';
const POLL_INTERVAL_MS = 5_000;
const POLL_TIMEOUT_MS = 5 * 60 * 1_000;

interface CuckooScanResult {
  task_id: string;
  report: CuckooReport;
  score: number;
}

@Injectable()
export class CuckooClient {
  private readonly log = new Logger(CuckooClient.name);
  private readonly config = loadConfig();

  isLive(): boolean {
    return Boolean(this.config.cuckoo.url);
  }

  async scan(submission: Submission): Promise<CuckooScanResult> {
    if (this.isLive()) {
      return this.scanLive(submission);
    }
    return this.scanMock(submission);
  }

  // ── In-process mock ───────────────────────────────────────────────
  private scanMock(submission: Submission): CuckooScanResult {
    const isEicar = submission.bytes.toString('utf8').includes(EICAR_MARKER);
    const taskId = `task_${randomUUID()}`;
    const submittedAt = new Date().toISOString();
    const completedAt = new Date(Date.now() + 1_000).toISOString();

    const report: CuckooReport = isEicar
      ? {
          cuckoo_task_id: taskId,
          submitted_at: submittedAt,
          completed_at: completedAt,
          signatures: [{ name: 'eicar_signature', severity: 3 }],
          network_iocs: [],
          file_iocs: [{ sha256: submission.sha256, name: submission.filename }],
          raw_report: {
            mock: true,
            info: { id: taskId, score: 9.2 },
            target: { file: { name: submission.filename, sha256: submission.sha256 } },
            signatures: [{ name: 'eicar_signature', severity: 3 }],
          },
        }
      : {
          cuckoo_task_id: taskId,
          submitted_at: submittedAt,
          completed_at: completedAt,
          signatures: [],
          network_iocs: [],
          file_iocs: [{ sha256: submission.sha256, name: submission.filename }],
          raw_report: { mock: true, info: { id: taskId, score: 0 } },
        };
    this.log.debug(`mock cuckoo task=${taskId} eicar=${isEicar}`);
    return { task_id: taskId, report, score: isEicar ? 9.2 : 0 };
  }

  // ── Live Cuckoo REST ──────────────────────────────────────────────
  private async scanLive(submission: Submission): Promise<CuckooScanResult> {
    const base = this.config.cuckoo.url!;
    const submittedAt = new Date().toISOString();

    // POST /tasks/create/file (multipart). Build the body manually so
    // we don't need a form-data dep just for one call.
    const boundary = `----mis${randomUUID().replace(/-/g, '')}`;
    const head = Buffer.from(
      `--${boundary}\r\n` +
        `Content-Disposition: form-data; name="file"; filename="${submission.filename}"\r\n` +
        `Content-Type: ${submission.content_type ?? 'application/octet-stream'}\r\n\r\n`,
    );
    const tail = Buffer.from(`\r\n--${boundary}--\r\n`);
    const body = Buffer.concat([head, submission.bytes, tail]);

    const createRes = await fetch(`${base}/tasks/create/file`, {
      method: 'POST',
      headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}` },
      body,
    });
    if (!createRes.ok) {
      throw new Error(`cuckoo create failed: HTTP ${createRes.status}`);
    }
    const { task_id } = (await createRes.json()) as { task_id: number };

    // Poll /tasks/view until task is `reported` (Cuckoo's done state).
    const deadline = Date.now() + POLL_TIMEOUT_MS;
    let lastStatus = 'pending';
    while (Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
      const viewRes = await fetch(`${base}/tasks/view/${task_id}`);
      if (!viewRes.ok) continue;
      const view = (await viewRes.json()) as { task?: { status?: string } };
      lastStatus = view.task?.status ?? lastStatus;
      if (lastStatus === 'reported' || lastStatus === 'completed') break;
    }
    if (lastStatus !== 'reported' && lastStatus !== 'completed') {
      throw new Error(`cuckoo task ${task_id} timed out (last status: ${lastStatus})`);
    }

    const reportRes = await fetch(`${base}/tasks/report/${task_id}`);
    if (!reportRes.ok) {
      throw new Error(`cuckoo report fetch failed: HTTP ${reportRes.status}`);
    }
    const raw = (await reportRes.json()) as any;
    const completedAt = new Date().toISOString();
    const score = Number(raw?.info?.score ?? 0);
    const signatures = Array.isArray(raw?.signatures)
      ? raw.signatures.map((s: any) => ({ name: String(s.name), severity: Number(s.severity ?? 1) }))
      : [];
    const networkIocs: string[] = [
      ...(raw?.network?.hosts?.map((h: any) => `host:${h.ip}`) ?? []),
      ...(raw?.network?.domains?.map((d: any) => `domain:${d.domain}`) ?? []),
    ];
    const fileIocs = [
      { sha256: submission.sha256, name: submission.filename },
      ...((raw?.dropped ?? []).map((d: any) => ({
        sha256: String(d.sha256 ?? ''),
        name: String(d.name ?? ''),
      }))),
    ];

    return {
      task_id: `task_${task_id}`,
      score,
      report: {
        cuckoo_task_id: `task_${task_id}`,
        submitted_at: submittedAt,
        completed_at: completedAt,
        signatures,
        network_iocs: networkIocs,
        file_iocs: fileIocs,
        raw_report: raw,
      },
    };
  }
}
