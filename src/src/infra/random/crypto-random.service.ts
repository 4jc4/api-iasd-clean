import { Injectable } from '@nestjs/common';
import { randomBytes } from 'crypto';
import { RandomGenerator } from '@domain/shared/services/random-generator';

@Injectable()
export class CryptoRandomService implements RandomGenerator {
  randomBytes(size: number): Promise<Uint8Array> {
    const bytes = new Uint8Array(randomBytes(size));
    return Promise.resolve(bytes);
  }

  toBase64url(bytes: Uint8Array): string {
    const base64 = Buffer.from(bytes).toString('base64');
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  }
}
