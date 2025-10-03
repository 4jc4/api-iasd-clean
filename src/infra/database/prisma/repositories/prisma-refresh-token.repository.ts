import { Injectable } from '@nestjs/common';
import { PrismaService } from '@infra/database/prisma/prisma.service';
import { RefreshTokenRepository } from '@domain/auth/repositories/refresh-token.repository';
import { RefreshToken } from '@domain/auth/entities/refresh-token.entity';
import { PrismaRefreshTokenMapper } from '../mappers/prisma-refresh-token.mapper';
import { InvariantViolationError } from '@domain/shared/errors/invariant-violation.error';

@Injectable()
export class PrismaRefreshTokenRepository implements RefreshTokenRepository {
  constructor(private readonly prisma: PrismaService) {}

  async findById(id: string): Promise<RefreshToken | null> {
    const raw = await this.prisma.refreshToken.findUnique({ where: { id } });
    return raw ? PrismaRefreshTokenMapper.toDomain(raw) : null;
  }

  async save(token: RefreshToken): Promise<void> {
    await this.prisma.refreshToken.upsert({
      where: { id: token.id },
      create: {
        id: token.id,
        userId: token.userId,
        secretHash: token.secretHash,
        familyId: token.familyId,
        createdAt: token.createdAt,
        expiresAt: token.expiresAt,
        revokedAt: token.revokedAt ?? null,
        replacedByTokenId: token.replacedByTokenId ?? null,
        createdByIp: token.createdByIp ?? null,
        userAgent: token.userAgent ?? null,
        lastUsedAt: token.lastUsedAt ?? null,
      },
      update: {
        secretHash: token.secretHash,
        familyId: token.familyId,
        expiresAt: token.expiresAt,
        revokedAt: token.revokedAt ?? null,
        replacedByTokenId: token.replacedByTokenId ?? null,
        createdByIp: token.createdByIp ?? null,
        userAgent: token.userAgent ?? null,
        lastUsedAt: token.lastUsedAt ?? null,
      },
    });
  }

  async revokeFamily(
    userId: string,
    familyId: string,
    now: Date,
  ): Promise<void> {
    await this.prisma.refreshToken.updateMany({
      where: { userId, familyId, revokedAt: null },
      data: { revokedAt: now },
    });
  }

  async findLatestByFamily(
    userId: string,
    familyId: string,
  ): Promise<RefreshToken | null> {
    const raw = await this.prisma.refreshToken.findFirst({
      where: {
        userId,
        familyId,
        revokedAt: null,
        replacedByTokenId: null,
      },
      orderBy: { createdAt: 'desc' },
    });
    return raw ? PrismaRefreshTokenMapper.toDomain(raw) : null;
  }

  async findActiveById(id: string, now: Date): Promise<RefreshToken | null> {
    const raw = await this.prisma.refreshToken.findFirst({
      where: {
        id,
        revokedAt: null,
        expiresAt: { gt: now },
      },
    });
    return raw ? PrismaRefreshTokenMapper.toDomain(raw) : null;
  }

  async replaceAndInsertAtomic(
    replaced: RefreshToken,
    next: RefreshToken,
  ): Promise<void> {
    await this.prisma.$transaction(async (tx) => {
      const updated = await tx.refreshToken.updateMany({
        where: {
          id: replaced.id,
          revokedAt: null,
          replacedByTokenId: null,
        },
        data: {
          revokedAt: replaced.revokedAt,
          replacedByTokenId: replaced.replacedByTokenId,
          lastUsedAt: replaced.lastUsedAt ?? null,
        },
      });

      if (updated.count !== 1) {
        throw new InvariantViolationError(
          'Concurrent rotation detected or token no longer in a rotatable state',
        );
      }

      await tx.refreshToken.create({
        data: {
          id: next.id,
          userId: next.userId,
          secretHash: next.secretHash,
          familyId: next.familyId,
          createdAt: next.createdAt,
          expiresAt: next.expiresAt,
          revokedAt: next.revokedAt ?? null,
          replacedByTokenId: next.replacedByTokenId ?? null,
          createdByIp: next.createdByIp ?? null,
          userAgent: next.userAgent ?? null,
          lastUsedAt: next.lastUsedAt ?? null,
        },
      });
    });
  }
}
