import { RotateRefreshTokenUseCase } from '@/domain/auth/use-cases/rotate-refresh-token.use-case';
import { RefreshTokenRepository } from '@/domain/auth/repositories/refresh-token.repository';
import { UserRepository } from '@/domain/users/repositories/user.repository';
import { HashGenerator } from '@/domain/shared/services/hash-generator';
import { UuidGenerator } from '@/domain/shared/services/uuid-generator';
import { Clock } from '@/domain/shared/services/clock';
import { RandomGenerator } from '@/domain/shared/services/random-generator';
import { TokenSigner } from '@/domain/auth/services/token-signer';
import { RefreshToken } from '@/domain/auth/entities/refresh-token.entity';
import { Role } from '@/domain/users/enums/role.enum';
import { User } from '@/domain/users/entities/user.entity';
import { RefreshTokenReuseDetectedError } from '@/domain/auth/errors/auth.errors';

describe('RotateRefreshTokenUseCase', () => {
  const createdAt = new Date('2024-01-01T00:00:00.000Z');
  const now = new Date('2024-01-01T01:00:00.000Z');
  const expiresAt = new Date('2024-01-08T00:00:00.000Z');

  const makeSut = () => {
    const rtRepo: jest.Mocked<RefreshTokenRepository> = {
      findById: jest.fn(),
      save: jest.fn(),
      revokeFamily: jest.fn(),
      findLatestByFamily: jest.fn(),
      findActiveById: jest.fn(),
      replaceAndInsertAtomic: jest.fn().mockResolvedValue(undefined),
    };
    const users: jest.Mocked<UserRepository> = {
      findById: jest.fn(),
      findByEmail: jest.fn(),
      save: jest.fn(),
    };
    const hash: jest.Mocked<HashGenerator> = {
      hash: jest.fn().mockResolvedValue('new-hash'),
      compare: jest.fn().mockResolvedValue(true),
    };
    const uuid: jest.Mocked<UuidGenerator> = {
      generate: jest.fn().mockReturnValue('rt-new'),
    };
    const clock: jest.Mocked<Clock> = {
      now: jest.fn().mockReturnValue(now),
    };
    const rnd: jest.Mocked<RandomGenerator> = {
      randomBytes: jest.fn().mockResolvedValue(new Uint8Array([9, 9, 9])),
      toBase64url: jest.fn().mockReturnValue('CQkJ'),
    };
    const signer: jest.Mocked<TokenSigner> = {
      signAccessToken: jest.fn().mockReturnValue('new.access.jwt'),
      verifyAccessToken: jest.fn(),
    };
    const config = {
      accessTokenTtl: '15m',
      refreshTokenTtlMs: 7 * 24 * 60 * 60 * 1000,
    };
    const sut = new RotateRefreshTokenUseCase(
      rtRepo,
      users,
      hash,
      uuid,
      clock,
      rnd,
      signer,
      config,
    );
    return { sut, rtRepo, users, hash, uuid, clock, rnd, signer, config };
  };

  it('rotates successfully when presented token is latest in family', async () => {
    const { sut, rtRepo, users, hash } = makeSut();
    const current = RefreshToken.rehydrate({
      id: 'rt-1',
      userId: 'u-1',
      secretHash: 'hash-1',
      familyId: 'fam-1',
      createdAt,
      expiresAt,
      revokedAt: null,
      replacedByTokenId: null,
      createdByIp: '127.0.0.1',
      userAgent: 'jest',
      lastUsedAt: null,
    });
    rtRepo.findById.mockResolvedValue(current);
    rtRepo.findLatestByFamily.mockResolvedValue(current);
    users.findById.mockResolvedValue(
      User.rehydrate({
        id: 'u-1',
        email: 'u@mail.com',
        name: 'U',
        passwordHash: 'x',
        role: Role.USER,
        createdAt,
        updatedAt: createdAt,
      }),
    );
    hash.compare.mockResolvedValue(true);
    const out = await sut.execute({ refreshToken: 'rt-1.AQID' });
    expect(out.accessToken).toBe('new.access.jwt');
    expect(out.refreshToken).toMatch(/^rt-new\.CQkJ$/);
    expect(rtRepo.replaceAndInsertAtomic).toHaveBeenCalledTimes(1);
    expect(rtRepo.replaceAndInsertAtomic).toHaveBeenCalledWith(
      current,
      expect.any(RefreshToken),
    );
  });

  it('detects reuse and revokes family', async () => {
    const { sut, rtRepo, users, hash } = makeSut();
    const current = RefreshToken.rehydrate({
      id: 'rt-old',
      userId: 'u-1',
      secretHash: 'hash-1',
      familyId: 'fam-1',
      createdAt,
      expiresAt,
      revokedAt: null,
      replacedByTokenId: 'rt-new-already',
      createdByIp: null,
      userAgent: null,
      lastUsedAt: null,
    });
    rtRepo.findById.mockResolvedValue(current);
    rtRepo.findLatestByFamily.mockResolvedValue(
      RefreshToken.rehydrate({
        id: 'rt-new-already',
        userId: 'u-1',
        secretHash: 'hash-2',
        familyId: 'fam-1',
        createdAt,
        expiresAt,
        revokedAt: null,
        replacedByTokenId: null,
        createdByIp: null,
        userAgent: null,
        lastUsedAt: null,
      }),
    );
    users.findById.mockResolvedValue(
      User.rehydrate({
        id: 'u-1',
        email: 'u@mail.com',
        name: 'U',
        passwordHash: 'x',
        role: Role.USER,
        createdAt,
        updatedAt: createdAt,
      }),
    );
    hash.compare.mockResolvedValue(true);
    await expect(sut.execute({ refreshToken: 'rt-old.AQID' })).rejects.toThrow(
      RefreshTokenReuseDetectedError,
    );
    expect(rtRepo.revokeFamily).toHaveBeenCalled();
    expect(rtRepo.replaceAndInsertAtomic).not.toHaveBeenCalled();
  });

  it('rotates successfully and audits lastUsedAt when presented token is latest in family', async () => {
    const { sut, rtRepo, users, hash } = makeSut();
    const current = RefreshToken.rehydrate({
      id: 'rt-1',
      userId: 'u-1',
      secretHash: 'hash-1',
      familyId: 'fam-1',
      createdAt,
      expiresAt,
      revokedAt: null,
      replacedByTokenId: null,
      createdByIp: '127.0.0.1',
      userAgent: 'jest',
      lastUsedAt: null,
    });
    rtRepo.findById.mockResolvedValue(current);
    rtRepo.findLatestByFamily.mockResolvedValue(current);
    users.findById.mockResolvedValue(
      User.rehydrate({
        id: 'u-1',
        email: 'u@mail.com',
        name: 'U',
        passwordHash: 'x',
        role: Role.USER,
        createdAt,
        updatedAt: createdAt,
      }),
    );
    hash.compare.mockResolvedValue(true);
    const out = await sut.execute({ refreshToken: 'rt-1.AQID' });
    expect(out.accessToken).toBe('new.access.jwt');
    expect(out.refreshToken).toMatch(/^rt-new\.CQkJ$/);
    expect(rtRepo.replaceAndInsertAtomic).toHaveBeenCalledTimes(1);
    expect(current.lastUsedAt).toEqual(now);
  });

  it('throws RefreshTokenExpiredError when current token is expired', async () => {
    const { sut, rtRepo, users, hash } = makeSut();
    const createdAtLocal = new Date('2024-01-01T00:00:00.000Z');
    const expiresAtLocal = new Date('2024-01-01T00:10:00.000Z');
    const current = RefreshToken.rehydrate({
      id: 'rt-exp',
      userId: 'u-1',
      secretHash: 'hash-1',
      familyId: 'fam-1',
      createdAt: createdAtLocal,
      expiresAt: expiresAtLocal,
      revokedAt: null,
      replacedByTokenId: null,
      createdByIp: null,
      userAgent: null,
      lastUsedAt: null,
    });
    rtRepo.findById.mockResolvedValue(current);
    rtRepo.findLatestByFamily.mockResolvedValue(current);
    users.findById.mockResolvedValue(
      User.rehydrate({
        id: 'u-1',
        email: 'u@mail.com',
        name: 'U',
        passwordHash: 'x',
        role: Role.USER,
        createdAt: createdAtLocal,
        updatedAt: createdAtLocal,
      }),
    );
    hash.compare.mockResolvedValue(true);
    await expect(sut.execute({ refreshToken: 'rt-exp.AQID' })).rejects.toThrow(
      /expired/i,
    );
  });

  it('throws RefreshTokenRevokedError when current token is revoked', async () => {
    const { sut, rtRepo, users, hash } = makeSut();
    const createdAtLocal = new Date('2024-01-01T00:00:00.000Z');
    const expiresAtLocal = new Date('2024-01-02T00:00:00.000Z');
    const current = RefreshToken.rehydrate({
      id: 'rt-rev',
      userId: 'u-1',
      secretHash: 'hash-1',
      familyId: 'fam-1',
      createdAt: createdAtLocal,
      expiresAt: expiresAtLocal,
      revokedAt: new Date('2024-01-01T00:30:00.000Z'),
      replacedByTokenId: null,
      createdByIp: null,
      userAgent: null,
      lastUsedAt: null,
    });
    rtRepo.findById.mockResolvedValue(current);
    rtRepo.findLatestByFamily.mockResolvedValue(current);
    users.findById.mockResolvedValue(
      User.rehydrate({
        id: 'u-1',
        email: 'u@mail.com',
        name: 'U',
        passwordHash: 'x',
        role: Role.USER,
        createdAt: createdAtLocal,
        updatedAt: createdAtLocal,
      }),
    );
    hash.compare.mockResolvedValue(true);
    await expect(sut.execute({ refreshToken: 'rt-rev.AQID' })).rejects.toThrow(
      /revoked/i,
    );
  });

  it('throws RefreshTokenNotFoundError when secret does not match stored hash', async () => {
    const { sut, rtRepo, users, hash } = makeSut();
    const createdAtLocal = new Date('2024-01-01T00:00:00.000Z');
    const expiresAtLocal = new Date('2024-01-08T00:00:00.000Z');
    const current = RefreshToken.rehydrate({
      id: 'rt-id',
      userId: 'u-1',
      secretHash: 'stored-hash',
      familyId: 'fam-1',
      createdAt: createdAtLocal,
      expiresAt: expiresAtLocal,
      revokedAt: null,
      replacedByTokenId: null,
      createdByIp: null,
      userAgent: null,
      lastUsedAt: null,
    });
    rtRepo.findById.mockResolvedValue(current);
    rtRepo.findLatestByFamily.mockResolvedValue(current);
    users.findById.mockResolvedValue(
      User.rehydrate({
        id: 'u-1',
        email: 'u@mail.com',
        name: 'U',
        passwordHash: 'x',
        role: Role.USER,
        createdAt: createdAtLocal,
        updatedAt: createdAtLocal,
      }),
    );
    hash.compare.mockResolvedValue(false); // segredo não bate
    await expect(
      sut.execute({ refreshToken: 'rt-id.WRONGSECRET' }),
    ).rejects.toThrow(/not found/i);
  });
});
