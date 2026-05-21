// MongoDB client + cuckoo_reports writer. Persists the full report ahead
// of the verdict event (workflow doc §9).
//
// Tolerant of an unreachable Mongo: logs and continues so the service
// boots even when mis-dev infra is down. A `getStored` helper returns
// the persisted row for the GET /submissions/:id/report endpoint.

import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { MongoClient, Collection } from 'mongodb';
import { loadConfig } from './config';
import type { CuckooReport, Verdict } from './types';

export interface StoredCuckooReport extends CuckooReport {
  document_id: string;
  submission_id: string;
  classification: Verdict;
}

@Injectable()
export class MongoService implements OnModuleInit, OnModuleDestroy {
  private readonly log = new Logger(MongoService.name);
  private readonly config = loadConfig();
  private client?: MongoClient;
  private collection?: Collection<StoredCuckooReport>;

  async onModuleInit(): Promise<void> {
    if (!this.config.mongodb.uri) {
      this.log.warn('MONGODB_URI unset — cuckoo reports will be dropped (PoC mode)');
      return;
    }
    try {
      this.client = new MongoClient(this.config.mongodb.uri);
      await this.client.connect();
      const db = this.client.db(this.config.mongodb.db);
      this.collection = db.collection<StoredCuckooReport>(this.config.mongodb.collection);
      await this.collection.createIndex({ submission_id: 1 }, { unique: true });
      await this.collection.createIndex({ cuckoo_task_id: 1 });
      this.log.log(`mongo connected — ${this.config.mongodb.db}.${this.config.mongodb.collection}`);
    } catch (err: any) {
      this.log.error(`mongo connect failed: ${err?.message ?? err}`);
      this.client = undefined;
      this.collection = undefined;
    }
  }

  async onModuleDestroy(): Promise<void> {
    if (this.client) await this.client.close().catch(() => undefined);
  }

  async save(report: StoredCuckooReport): Promise<void> {
    if (!this.collection) {
      this.log.debug(`[drop] cuckoo_report submission=${report.submission_id}`);
      return;
    }
    await this.collection.replaceOne(
      { submission_id: report.submission_id },
      report,
      { upsert: true },
    );
  }

  async findBySubmission(submissionId: string): Promise<StoredCuckooReport | null> {
    if (!this.collection) return null;
    return this.collection.findOne({ submission_id: submissionId });
  }
}
