// Typed env loader. Centralised so we don't sprinkle process.env reads
// across the modules.

export interface SandboxConfig {
  port: number;
  mongodb: { uri?: string; db: string; collection: string };
  kafka: { brokers: string[]; clientId: string };
  cuckoo: { url?: string };
  topics: { progress: string; verdict: string };
}

export function loadConfig(): SandboxConfig {
  const brokers = (process.env.KAFKA_BROKERS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  return {
    port: Number(process.env.PORT) || 3004,
    mongodb: {
      uri: process.env.MONGODB_URI || undefined,
      db: process.env.MONGODB_DB || 'mis_sandbox',
      collection: 'cuckoo_reports',
    },
    kafka: {
      brokers,
      clientId: 'mis-sandbox-service',
    },
    // When unset the Cuckoo client falls back to the in-process mock
    // (see architecture/document-upload-workflow.md §6.2).
    cuckoo: { url: process.env.CUCKOO_URL || undefined },
    topics: {
      progress: 'mis.documents.scan-progress',
      verdict: 'mis.documents.verdict',
    },
  };
}
