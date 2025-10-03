import { Injectable } from '@nestjs/common';
import { Clock } from '@domain/shared/services/clock';

@Injectable()
export class SystemClock implements Clock {
  now(): Date {
    return new Date();
  }
}
