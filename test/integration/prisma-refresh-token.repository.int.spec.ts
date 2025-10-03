import { PrismaRefreshTokenRepository } from '@/infra/database/prisma/repositories/prisma-refresh-token.repository';
import { PrismaService } from '@/infra/database/prisma/prisma.service';
import { resetDatabase, disconnect } from './helpers/db';
import { RefreshToken } from '@/domain/auth/entities/refresh-token.entity';
import { InvariantViolationError } from '@/domain/shared/errors/invariant-violation.error';
import { Role } from '@/domain/users/enums/role.enum';
import { PrismaUserRepository } from '@/infra/database/prisma/repositories/prisma-user.repository';
import { User } from '@/domain/users/entities/user.entity';

describe('PrismaRefreshTokenRepository (integration)', () => {
  const prisma = new PrismaService();
  const rtRepo = new PrismaRefreshTokenRepository(prisma);
  const userRepo = new PrismaUserRepository(prisma);
  const createdAt = new Date('2024-01-01T00:00:00.000Z');

  beforeAll(async () => {
    await prisma.$connect();
  });

  afterAll(async () => {
    await resetDatabase();
    await disconnect();
  });

  beforeEach(async () => {
    await resetDatabase();
    const u = User.rehydrate({
      id: 'u-1',
      email: 'user@mail.com',
      name: 'User',
      passwordHash: 'hash',
      role: Role.USER,
      createdAt,
      updatedAt: createdAt,
    });
    await userRepo.save(u);
  });

  function makeToken(
    params?: Partial<{
      id: string;
      userId: string;
      secretHash: string;
      familyId: string;
      createdAt: Date;
      expiresAt: Date;
      revokedAt: Date | null;
      replacedByTokenId: string | null;
    }>,
  ) {
    return RefreshToken.rehydrate({
      id: params?.id ?? 'rt-1',
      userId: params?.userId ?? 'u-1',
      secretHash: params?.secretHash ?? 'hash-1',
      familyId: params?.familyId ?? 'fam-1',
      createdAt: params?.createdAt ?? createdAt,
      expiresAt: params?.expiresAt ?? new Date('2024-01-08T00:00:00.000Z'),
      revokedAt: params?.revokedAt ?? null,
      replacedByTokenId: params?.replacedByTokenId ?? null,
      createdByIp: null,
      userAgent: null,
      lastUsedAt: null,
    });
  }

  it('save (upsert) and findById', async () => {
    const t = makeToken();
    await rtRepo.save(t);
    const found = await rtRepo.findById('rt-1');
    expect(found).not.toBeNull();
    expect(found?.userId).toBe('u-1');
    expect(found?.familyId).toBe('fam-1');
  });

  it('findLatestByFamily returns the most recent non-revoked and non-replaced', async () => {
    const t1 = makeToken({
      id: 'rt-1',
      createdAt: new Date('2024-01-01T00:00:00Z'),
    });
    const t2 = makeToken({
      id: 'rt-2',
      createdAt: new Date('2024-01-02T00:00:00Z'),
    });
    const t3 = makeToken({
      id: 'rt-3',
      createdAt: new Date('2024-01-03T00:00:00Z'),
      revokedAt: null,
      replacedByTokenId: null,
    });
    await rtRepo.save(t1);
    await rtRepo.save(t2);
    await rtRepo.save(t3);
    const latest = await rtRepo.findLatestByFamily('u-1', 'fam-1');
    expect(latest?.id).toBe('rt-3');
  });

  it('findActiveById returns only if not revoked and not expired', async () => {
    const now = new Date('2024-01-05T00:00:00Z');
    const active = makeToken({
      id: 'rt-active',
      expiresAt: new Date('2024-01-10T00:00:00Z'),
    });
    const expired = makeToken({
      id: 'rt-exp',
      expiresAt: new Date('2024-01-02T00:00:00Z'),
    });
    const revoked = makeToken({
      id: 'rt-rev',
      revokedAt: new Date('2024-01-02T00:00:00Z'),
    });
    await rtRepo.save(active);
    await rtRepo.save(expired);
    await rtRepo.save(revoked);
    expect(await rtRepo.findActiveById('rt-active', now)).not.toBeNull();
    expect(await rtRepo.findActiveById('rt-exp', now)).toBeNull();
    expect(await rtRepo.findActiveById('rt-rev', now)).toBeNull();
  });

  it('revokeFamily sets revokedAt for all tokens of the family', async () => {
    const t1 = makeToken({ id: 'rt-a' });
    const t2 = makeToken({ id: 'rt-b' });
    await rtRepo.save(t1);
    await rtRepo.save(t2);
    const now = new Date('2024-01-06T00:00:00Z');
    await rtRepo.revokeFamily('u-1', 'fam-1', now);
    const a = await rtRepo.findById('rt-a');
    const b = await rtRepo.findById('rt-b');
    expect(a?.revokedAt).toEqual(now);
    expect(b?.revokedAt).toEqual(now);
  });

  it('replaceAndInsertAtomic rotates once and prevents a second rotation on the same token', async () => {
    const current = makeToken({ id: 'rt-cur' });
    await rtRepo.save(current);
    const now = new Date('2024-01-07T00:00:00Z');
    const newId = 'rt-next';
    current.replaceWith(newId, now);
    const next = makeToken({
      id: newId,
      createdAt: now,
      expiresAt: new Date('2024-01-14T00:00:00Z'),
      revokedAt: null,
      replacedByTokenId: null,
    });
    await rtRepo.replaceAndInsertAtomic(current, next);
    const curDb = await rtRepo.findById('rt-cur');
    const nextDb = await rtRepo.findById('rt-next');
    expect(curDb?.revokedAt).toEqual(now);
    expect(curDb?.replacedByTokenId).toBe('rt-next');
    expect(nextDb).not.toBeNull();
    const again = makeToken({ id: 'rt-cur' });
    again.replaceWith('rt-z', now);
    const z = makeToken({
      id: 'rt-z',
      createdAt: now,
      expiresAt: new Date('2024-01-15T00:00:00Z'),
    });
    await expect(
      rtRepo.replaceAndInsertAtomic(again, z),
    ).rejects.toBeInstanceOf(InvariantViolationError);
  });
});
