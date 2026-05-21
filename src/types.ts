// Shared types for the Sandbox Service scan pipeline.
// Shapes mirror the Kafka envelopes in
// architecture/document-upload-workflow.md §6.4 and §7.

export type Verdict = 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' | 'INCONCLUSIVE';

export type ScanStage =
  | 'submitted'
  | 'cuckoo'
  | 'clamav'
  | 'yara'
  | 'suricata'
  | 'aggregating'
  | 'done';

export interface SubmissionMetadata {
  document_id: string;
  parent_type?: string;
  parent_ref?: string;
  filename: string;
  content_type?: string;
  submitted_by?: string;
  correlation_id?: string;
  sha256: string;
}

export interface Submission extends SubmissionMetadata {
  submission_id: string;
  bytes: Buffer;
}

// A single scanner's verdict. `status` mirrors §7 inputs; `score` is
// Cuckoo-specific (0–10). evidence is human-readable IOC strings.
export interface ScannerResult {
  name: 'cuckoo' | 'clamav' | 'yara' | 'suricata';
  status: 'clean' | 'malicious' | 'malicious-rule' | 'malicious-alert' | 'suspicious' | 'error';
  score?: number;
  evidence?: string[];
  error?: string;
}

export interface CuckooReport {
  cuckoo_task_id: string;
  submitted_at: string;
  completed_at: string;
  signatures: Array<{ name: string; severity: number }>;
  network_iocs: string[];
  file_iocs: Array<{ sha256: string; name: string }>;
  raw_report: unknown;
}

export interface ProgressEvent {
  schema: 'mis.documents.scan-progress.v1';
  correlation_id?: string;
  document_id: string;
  submission_id: string;
  stage: ScanStage;
  progress_pct: number;
  started_at: string;
  cuckoo_task_id?: string;
}

export interface VerdictEvent {
  schema: 'mis.documents.verdict.v1';
  correlation_id?: string;
  document_id: string;
  submission_id: string;
  verdict: Verdict;
  verdict_at: string;
  scanner_results: ScannerResult[];
  cuckoo_task_id?: string;
}
