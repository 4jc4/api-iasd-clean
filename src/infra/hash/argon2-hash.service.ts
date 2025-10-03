import { Injectable } from '@nestjs/common';
import { HashGenerator } from '@domain/shared/services/hash-generator';
import * as argon2 from 'argon2';

function loadArgon2Options(): argon2.Options & { type: number } {
  const typeStr = (process.env.ARGON2_TYPE || 'id').toLowerCase();
  const type =
    typeStr === 'i'
      ? argon2.argon2i
      : typeStr === 'd'
        ? argon2.argon2d
        : argon2.argon2id;
  const memoryCost = parseInt(process.env.ARGON2_MEMORY_COST || '', 10);
  const timeCost = parseInt(process.env.ARGON2_TIME_COST || '', 10);
  const parallelism = parseInt(process.env.ARGON2_PARALLELISM || '', 10);
  const hashLength = parseInt(process.env.ARGON2_HASH_LENGTH || '', 10);
  const opts: argon2.Options & { type: number } = {
    type,
    memoryCost: Number.isFinite(memoryCost) ? memoryCost : 19456, // ~19 MiB
    timeCost: Number.isFinite(timeCost) ? timeCost : 3,
    parallelism: Number.isFinite(parallelism) ? parallelism : 1,
  };
  if (Number.isFinite(hashLength)) {
    opts.hashLength = hashLength;
  }
  return opts;
}

@Injectable()
export class Argon2HashService implements HashGenerator {
  private readonly options: argon2.Options & { type: number } =
    loadArgon2Options();

  async hash(payload: string): Promise<string> {
    return argon2.hash(payload, this.options);
  }

  async compare(payload: string, hashed: string): Promise<boolean> {
    return argon2.verify(hashed, payload, this.options);
  }
}
