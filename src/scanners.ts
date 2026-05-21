// In-process mock scanners. Each checks the submission bytes for the
// EICAR test signature and returns a deterministic result matching the
// schema in workflow doc §7.
//
// In production these wrap real engines (`clamscan`, YARA CLI, Suricata
// PCAP replay). Replacing them is a single-file change — the contract
// is just `(submission, cuckooScore?) => Promise<ScannerResult>`.

import { Injectable } from '@nestjs/common';
import type { CuckooReport, ScannerResult, Submission } from './types';

const EICAR_MARKER = 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE';

function hasEicar(submission: Submission): boolean {
  return submission.bytes.toString('utf8').includes(EICAR_MARKER);
}

@Injectable()
export class ClamAvScanner {
  async scan(submission: Submission): Promise<ScannerResult> {
    if (hasEicar(submission)) {
      return {
        name: 'clamav',
        status: 'malicious',
        evidence: ['Eicar-Test-Signature'],
      };
    }
    return { name: 'clamav', status: 'clean' };
  }
}

@Injectable()
export class YaraScanner {
  async scan(submission: Submission): Promise<ScannerResult> {
    if (hasEicar(submission)) {
      return {
        name: 'yara',
        status: 'malicious-rule',
        evidence: ['Eicar'],
      };
    }
    return { name: 'yara', status: 'clean' };
  }
}

@Injectable()
export class SuricataScanner {
  // Suricata only runs when Cuckoo produced network traffic. The mock
  // Cuckoo never does, so this returns clean. Kept here so the
  // orchestrator has a uniform call site.
  async scan(_submission: Submission, cuckooReport: CuckooReport): Promise<ScannerResult> {
    if (cuckooReport.network_iocs.length === 0) {
      return { name: 'suricata', status: 'clean' };
    }
    return {
      name: 'suricata',
      status: 'malicious-alert',
      evidence: cuckooReport.network_iocs,
    };
  }
}
