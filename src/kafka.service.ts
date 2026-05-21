// Thin Kafka producer wrapper. Publishes progress + verdict events for
// the document-upload workflow (see workflow doc §6.4 and §7).
//
// Tolerant of an unreachable broker: logs and continues so `make dev`
// still boots even if mis-dev infra isn't running. In a real deploy
// these failures would be hard errors.

import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { Kafka, Producer } from 'kafkajs';
import { loadConfig } from './config';
import type { ProgressEvent, VerdictEvent } from './types';

@Injectable()
export class KafkaService implements OnModuleInit, OnModuleDestroy {
  private readonly log = new Logger(KafkaService.name);
  private readonly config = loadConfig();
  private producer?: Producer;
  private connected = false;

  async onModuleInit(): Promise<void> {
    if (this.config.kafka.brokers.length === 0) {
      this.log.warn('KAFKA_BROKERS unset — progress/verdict events will be dropped (PoC mode)');
      return;
    }
    const kafka = new Kafka({
      clientId: this.config.kafka.clientId,
      brokers: this.config.kafka.brokers,
    });
    this.producer = kafka.producer({ idempotent: true, allowAutoTopicCreation: false });
    try {
      await this.producer.connect();
      this.connected = true;
      this.log.log(`kafka connected — brokers=${this.config.kafka.brokers.join(',')}`);
    } catch (err: any) {
      this.log.error(`kafka connect failed: ${err?.message ?? err}`);
      this.producer = undefined;
    }
  }

  async onModuleDestroy(): Promise<void> {
    if (this.producer) await this.producer.disconnect().catch(() => undefined);
  }

  async publishProgress(event: ProgressEvent): Promise<void> {
    await this.publish(this.config.topics.progress, event.document_id, event);
  }

  async publishVerdict(event: VerdictEvent): Promise<void> {
    await this.publish(this.config.topics.verdict, event.document_id, event);
  }

  private async publish(topic: string, key: string, value: unknown): Promise<void> {
    if (!this.producer || !this.connected) {
      this.log.debug(`[drop] ${topic} ${(value as any)?.stage ?? (value as any)?.verdict ?? ''}`);
      return;
    }
    try {
      await this.producer.send({
        topic,
        messages: [{ key, value: JSON.stringify(value) }],
      });
    } catch (err: any) {
      this.log.error(`kafka publish ${topic} failed: ${err?.message ?? err}`);
    }
  }
}
