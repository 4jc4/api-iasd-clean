import { RefreshToken } from '@domain/auth/entities/refresh-token.entity';

export abstract class RefreshTokenRepository {
  abstract findById(id: string): Promise<RefreshToken | null>;
  abstract save(token: RefreshToken): Promise<void>;
  abstract revokeFamily(
    userId: string,
    familyId: string,
    now: Date,
  ): Promise<void>;
  abstract findLatestByFamily(
    userId: string,
    familyId: string,
  ): Promise<RefreshToken | null>;
  abstract findActiveById(id: string, now: Date): Promise<RefreshToken | null>;
  abstract replaceAndInsertAtomic(
    replaced: RefreshToken,
    next: RefreshToken,
  ): Promise<void>;
}
