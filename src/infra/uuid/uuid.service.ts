import { Injectable } from '@nestjs/common';
import { randomUUID } from 'crypto';
import { UuidGenerator } from '@domain/shared/services/uuid-generator';

@Injectable()
export class UuidService extends UuidGenerator {
  generate(): string {
    return randomUUID();
  }
}
