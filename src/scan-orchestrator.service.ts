// Drives a submission through the full scan pipeline.
//
// Sequence (workflow doc §3, §6, §7):
//   1. emit progress "submitted"
//   2. invoke Cuckoo (live or mock) — emit "cuckoo"
//   3. run ClamAV + YARA + Suricata in parallel — emit each stage
//   4. emit "aggregating", apply §7 decision table → verdict
//   5. persist mongo.cuckoo_reports
//   6. emit "done" progress, then the final verdict on mis.documents.verdict
//
// Runs async after the HTTP controller returns 202 to the caller, so a
// 5-minute Cuckoo task doesn't block the response.

import { Injectable, Logger } from '@nestjs/common';
import { CuckooClient } from './cuckoo.client';
import { KafkaService } from './kafka.service';
import { MongoService } from './mongo.service';
import { ClamAvScanner, SuricataScanner, YaraScanner } from './scanners';
import type {
  ProgressEvent,
  ScannerResult,
  ScanStage,
  Submission,
  Verdict,
  VerdictEvent,
} from './types';

interface StageProgress {
  stage: ScanStage;
  pct: number;
}

const PCT: Record<ScanStage, number> = {
  submitted: 5,
  cuckoo: 20,
  clamav: 60,
  yara: 75,
  suricata: 90,
  aggregating: 95,
  done: 100,
};

@Injectable()
export class ScanOrchestrator {
  private readonly log = new Logger(ScanOrchestrator.name);

  constructor(
    private readonly cuckoo: CuckooClient,
    private readonly clamav: ClamAvScanner,
    private readonly yara: YaraScanner,
    private readonly suricata: SuricataScanner,
    private readonly kafka: KafkaService,
    private readonly mongo: MongoService,
  ) {}

  // Fire-and-forget. Errors are logged and surfaced as an INCONCLUSIVE
  // verdict so the Document Service consumer always sees a terminal event.
  run(submission: Submission): void {
    this.execute(submission).catch((err) => {
      this.log.error(
        `submission=${submission.submission_id} pipeline crashed: ${err?.message ?? err}`,
      );
    });
  }

  private async execute(submission: Submission): Promise<void> {
    const { submission_id, document_id, correlation_id } = submission;
    this.log.log(
      `submission.accepted submission_id=${submission_id} doc=${document_id} ` +
        `cuckoo=${this.cuckoo.isLive() ? 'live' : 'mock'}`,
    );

    let cuckooTaskId: string | undefined;
    const results: ScannerResult[] = [];

    await this.emitProgress(submission, { stage: 'submitted', pct: PCT.submitted });

    // 1) Cuckoo behavioural — gates the parallel scanners because YARA
    // and Suricata want the Cuckoo report.
    let cuckooScore = 0;
    let cuckooReport;
    try {
      await this.emitProgress(submission, { stage: 'cuckoo', pct: PCT.cuckoo });
      const result = await this.cuckoo.scan(submission);
      cuckooTaskId = result.task_id;
      cuckooScore = result.score;
      cuckooReport = result.report;
      results.push({
        name: 'cuckoo',
        status: cuckooScore >= 8 ? 'malicious' : cuckooScore >= 5 ? 'suspicious' : 'clean',
        score: cuckooScore,
        evidence: cuckooReport.signatures.map((s) => s.name),
      });
    } catch (err: any) {
      this.log.error(`cuckoo failed: ${err?.message ?? err}`);
      results.push({ name: 'cuckoo', status: 'error', error: String(err?.message ?? err) });
      cuckooReport = undefined;
    }

    // 2) Parallel scanners — each emits its own progress event.
    if (cuckooReport) {
      const [clam, yara, suri] = await Promise.all([
        this.withProgress(submission, 'clamav', () => this.clamav.scan(submission)),
        this.withProgress(submission, 'yara', () => this.yara.scan(submission)),
        this.withProgress(submission, 'suricata', () =>
          this.suricata.scan(submission, cuckooReport!),
        ),
      ]);
      results.push(clam, yara, suri);
    }

    // 3) Aggregate.
    await this.emitProgress(submission, { stage: 'aggregating', pct: PCT.aggregating });
    const verdict = aggregate(results);

    // 4) Persist before emitting the verdict — workflow doc §9: the
    // Document Service consumer relies on the report being queryable
    // by the time it sees the verdict event.
    if (cuckooReport) {
      await this.mongo.save({
        ...cuckooReport,
        document_id,
        submission_id,
        classification: verdict,
      });
    }

    await this.emitProgress(submission, { stage: 'done', pct: PCT.done, cuckoo_task_id: cuckooTaskId });

    const verdictEvent: VerdictEvent = {
      schema: 'mis.documents.verdict.v1',
      correlation_id,
      document_id,
      submission_id,
      verdict,
      verdict_at: new Date().toISOString(),
      scanner_results: results,
      cuckoo_task_id: cuckooTaskId,
    };
    await this.kafka.publishVerdict(verdictEvent);
    this.log.log(
      `verdict.published submission_id=${submission_id} doc=${document_id} verdict=${verdict}`,
    );
  }

  private async withProgress<T extends ScannerResult>(
    submission: Submission,
    stage: ScanStage,
    fn: () => Promise<T>,
  ): Promise<T> {
    await this.emitProgress(submission, { stage, pct: PCT[stage] });
    try {
      return await fn();
    } catch (err: any) {
      const errored: ScannerResult = {
        name: stage as ScannerResult['name'],
        status: 'error',
        error: String(err?.message ?? err),
      };
      return errored as T;
    }
  }

  private async emitProgress(
    submission: Submission,
    progress: StageProgress & { cuckoo_task_id?: string },
  ): Promise<void> {
    const event: ProgressEvent = {
      schema: 'mis.documents.scan-progress.v1',
      correlation_id: submission.correlation_id,
      document_id: submission.document_id,
      submission_id: submission.submission_id,
      stage: progress.stage,
      progress_pct: progress.pct,
      started_at: new Date().toISOString(),
      cuckoo_task_id: progress.cuckoo_task_id,
    };
    this.log.debug(`progress.emitted stage=${progress.stage} pct=${progress.pct}`);
    await this.kafka.publishProgress(event);
  }
}

// Decision table per workflow doc §7 (most severe wins). Treat any
// `error` as INCONCLUSIVE → downstream policy demotes to SUSPICIOUS.
function aggregate(results: ScannerResult[]): Verdict {
  if (results.some((r) => r.status === 'error')) return 'INCONCLUSIVE';
  if (results.some((r) => r.status === 'malicious')) return 'MALICIOUS';
  if (results.some((r) => r.status === 'malicious-rule')) return 'MALICIOUS';
  if (results.some((r) => r.status === 'malicious-alert')) return 'MALICIOUS';
  const cuckoo = results.find((r) => r.name === 'cuckoo');
  if (cuckoo && typeof cuckoo.score === 'number' && cuckoo.score >= 8) return 'MALICIOUS';
  if (results.some((r) => r.status === 'suspicious')) return 'SUSPICIOUS';
  return 'SAFE';
}
