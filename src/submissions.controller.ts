// HTTP entry point — POST /api/sandbox/submissions.
//
// In production this is the gRPC SandboxService.SubmitFile stream
// (workflow doc §6, arch 03 §4.2). The PoC uses plain HTTP multipart
// so the Document Service can call it without a proto client; the
// Kafka events fired by the orchestrator are identical either way.

import {
  BadRequestException,
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  NotFoundException,
  Param,
  Post,
  Req,
  UploadedFile,
  UseInterceptors,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { createHash, randomUUID } from 'node:crypto';
import { MongoService } from './mongo.service';
import { ScanOrchestrator } from './scan-orchestrator.service';
import type { Submission } from './types';

const SERVICE = 'mis-sandbox-service';

interface SubmissionMetadataBody {
  document_id?: string;
  parent_type?: string;
  parent_ref?: string;
  submitted_by?: string;
  filename?: string;
  content_type?: string;
}

@Controller('submissions')
export class SubmissionsController {
  constructor(
    private readonly orchestrator: ScanOrchestrator,
    private readonly mongo: MongoService,
  ) {}

  // Multipart with one file field (`file`) and a JSON `metadata` field.
  // 202 Accepted because the scan runs async; caller polls Kafka or the
  // GET below for the persisted report.
  @Post()
  @HttpCode(HttpStatus.ACCEPTED)
  @UseInterceptors(FileInterceptor('file', { limits: { fileSize: 50 * 1024 * 1024 } }))
  submit(
    @UploadedFile() file: Express.Multer.File | undefined,
    @Body() body: { metadata?: string | SubmissionMetadataBody },
    @Req() req: any,
  ) {
    if (!file) {
      throw new BadRequestException('missing `file` field (multipart)');
    }
    const meta = parseMetadata(body?.metadata);
    if (!meta.document_id) {
      throw new BadRequestException('metadata.document_id is required');
    }

    const submission: Submission = {
      submission_id: `sub_${randomUUID()}`,
      document_id: meta.document_id,
      parent_type: meta.parent_type,
      parent_ref: meta.parent_ref,
      submitted_by: meta.submitted_by,
      filename: meta.filename ?? file.originalname,
      content_type: meta.content_type ?? file.mimetype,
      correlation_id: req.correlationId ?? req.headers?.['x-correlation-id'],
      sha256: createHash('sha256').update(file.buffer).digest('hex'),
      bytes: file.buffer,
    };

    // Kick off the pipeline async; reply immediately.
    this.orchestrator.run(submission);

    return {
      service: SERVICE,
      submission_id: submission.submission_id,
      document_id: submission.document_id,
      sha256: submission.sha256,
      accepted_at: new Date().toISOString(),
    };
  }

  // Fetch the persisted cuckoo report — used by the Admin Service /
  // case-svc test driver to inspect what was actually written.
  @Get(':submissionId/report')
  async report(@Param('submissionId') submissionId: string) {
    const stored = await this.mongo.findBySubmission(submissionId);
    if (!stored) throw new NotFoundException(`no report for ${submissionId}`);
    return stored;
  }
}

function parseMetadata(raw: unknown): SubmissionMetadataBody {
  if (!raw) return {};
  if (typeof raw === 'object') return raw as SubmissionMetadataBody;
  try {
    return JSON.parse(String(raw));
  } catch {
    throw new BadRequestException('metadata must be valid JSON');
  }
}
