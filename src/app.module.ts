import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { SubmissionsController } from './submissions.controller';
import { ScanOrchestrator } from './scan-orchestrator.service';
import { CuckooClient } from './cuckoo.client';
import { ClamAvScanner, SuricataScanner, YaraScanner } from './scanners';
import { KafkaService } from './kafka.service';
import { MongoService } from './mongo.service';

@Module({
  controllers: [AppController, SubmissionsController],
  providers: [
    ScanOrchestrator,
    CuckooClient,
    ClamAvScanner,
    YaraScanner,
    SuricataScanner,
    KafkaService,
    MongoService,
  ],
})
export class AppModule {}
