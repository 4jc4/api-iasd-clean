import { RefreshToken as PrismaRT } from '@prisma/client';
import { RefreshToken } from '@domain/auth/entities/refresh-token.entity';

export const PrismaRefreshTokenMapper = {
  toDomain(raw: PrismaRT): RefreshToken {
    return RefreshToken.rehydrate({
      id: raw.id,
      userId: raw.userId,
      secretHash: raw.secretHash,
      familyId: raw.familyId,
      createdAt: raw.createdAt,
      expiresAt: raw.expiresAt,
      revokedAt: raw.revokedAt ?? null,
      replacedByTokenId: raw.replacedByTokenId ?? null,
      createdByIp: raw.createdByIp ?? null,
      userAgent: raw.userAgent ?? null,
      lastUsedAt: raw.lastUsedAt ?? null,
    });
  },
};
