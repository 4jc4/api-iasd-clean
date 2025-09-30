import { AuthenticateUserUseCase } from '@/domain/auth/use-cases/authenticate-user.use-case';
import { UserRepository } from '@/domain/users/repositories/user.repository';
import { RefreshTokenRepository } from '@/domain/auth/repositories/refresh-token.repository';
import { HashGenerator } from '@/domain/shared/services/hash-generator';
import { RandomGenerator } from '@/domain/shared/services/random-generator';
import { UuidGenerator } from '@/domain/shared/services/uuid-generator';
import { Clock } from '@/domain/shared/services/clock';
import { TokenSigner } from '@/domain/auth/services/token-signer';
import { User } from '@/domain/users/entities/user.entity';
import { Role } from '@/domain/users/enums/role.enum';
import { InvalidCredentialsError } from '@/domain/auth/errors/auth.errors';

describe('AuthenticateUserUseCase', () => {
  const fixedDate = new Date('2024-01-01T00:00:00.000Z');
  const makeSut = () => {
    const users: jest.Mocked<UserRepository> = {
      findById: jest.fn(),
      findByEmail: jest.fn(),
      save: jest.fn(),
    };
    const rtRepo: jest.Mocked<RefreshTokenRepository> = {
      findById: jest.fn(),
      save: jest.fn(),
      revokeFamily: jest.fn(),
      findLatestByFamily: jest.fn(),
      findActiveById: jest.fn(),
      replaceAndInsertAtomic: jest.fn().mockResolvedValue(undefined),
    };
    const hash: jest.Mocked<HashGenerator> = {
      hash: jest.fn().mockResolvedValue('hashed-secret'),
      compare: jest.fn().mockResolvedValue(true),
    };
    const rnd: jest.Mocked<RandomGenerator> = {
      randomBytes: jest.fn().mockResolvedValue(new Uint8Array([1, 2, 3])),
      toBase64url: jest.fn().mockReturnValue('AQID'),
    };
    const uuid: jest.Mocked<UuidGenerator> = {
      generate: jest
        .fn()
        .mockReturnValueOnce('family-1')
        .mockReturnValue('rt-1'),
    };
    const clock: jest.Mocked<Clock> = {
      now: jest.fn().mockReturnValue(fixedDate),
    };
    const signer: jest.Mocked<TokenSigner> = {
      signAccessToken: jest.fn().mockReturnValue('access.jwt.token'),
      verifyAccessToken: jest.fn(),
    };
    const config = {
      accessTokenTtl: '15m',
      refreshTokenTtlMs: 7 * 24 * 60 * 60 * 1000,
    };
    const sut = new AuthenticateUserUseCase(
      users,
      rtRepo,
      hash,
      rnd,
      uuid,
      clock,
      signer,
      config,
    );
    return { sut, users, rtRepo, hash, rnd, uuid, clock, signer, config };
  };

  it('authenticates and issues tokens (happy path)', async () => {
    const { sut, users, rtRepo } = makeSut();
    users.findByEmail.mockResolvedValue(
      User.rehydrate({
        id: 'u-1',
        email: 'user@mail.com',
        name: 'User',
        passwordHash: 'stored-hash',
        role: Role.USER,
        createdAt: fixedDate,
        updatedAt: fixedDate,
      }),
    );
    const out = await sut.execute({ email: 'user@mail.com', password: 'pwd' });
    expect(out.accessToken).toBe('access.jwt.token');
    expect(out.refreshToken).toMatch(/^rt-1\.AQID$/);
    expect(rtRepo.save).toHaveBeenCalledTimes(1);
  });

  it('throws on invalid credentials', async () => {
    const { sut, users, hash } = makeSut();
    users.findByEmail.mockResolvedValue(
      User.rehydrate({
        id: 'u-1',
        email: 'user@mail.com',
        name: 'User',
        passwordHash: 'stored-hash',
        role: Role.USER,
        createdAt: fixedDate,
        updatedAt: fixedDate,
      }),
    );
    hash.compare.mockResolvedValue(false);
    await expect(
      sut.execute({ email: 'user@mail.com', password: 'bad' }),
    ).rejects.toThrow(InvalidCredentialsError);
  });

  it('throws when RandomGenerator returns empty bytes (invariant)', async () => {
    const users: jest.Mocked<UserRepository> = {
      findById: jest.fn(),
      findByEmail: jest.fn().mockResolvedValue(
        User.rehydrate({
          id: 'u-1',
          email: 'user@mail.com',
          name: 'User',
          passwordHash: 'stored-hash',
          role: Role.USER,
          createdAt: fixedDate,
          updatedAt: fixedDate,
        }),
      ),
      save: jest.fn(),
    };
    const rtRepo: jest.Mocked<RefreshTokenRepository> = {
      findById: jest.fn(),
      save: jest.fn(),
      revokeFamily: jest.fn(),
      findLatestByFamily: jest.fn(),
      findActiveById: jest.fn(),
      replaceAndInsertAtomic: jest.fn(),
    };
    const hash: jest.Mocked<HashGenerator> = {
      hash: jest.fn(),
      compare: jest.fn().mockResolvedValue(true),
    };
    const rnd: jest.Mocked<RandomGenerator> = {
      randomBytes: jest.fn().mockResolvedValue(new Uint8Array([])), // ⛔ empty
      toBase64url: jest.fn(),
    };
    const uuid: jest.Mocked<UuidGenerator> = {
      generate: jest.fn().mockReturnValue('id'),
    };
    const clock: jest.Mocked<Clock> = {
      now: jest.fn().mockReturnValue(fixedDate),
    };
    const signer: jest.Mocked<TokenSigner> = {
      signAccessToken: jest.fn(),
      verifyAccessToken: jest.fn(),
    };
    const sut = new AuthenticateUserUseCase(
      users,
      rtRepo,
      hash,
      rnd,
      uuid,
      clock,
      signer,
      { accessTokenTtl: '15m', refreshTokenTtlMs: 7 * 24 * 60 * 60 * 1000 },
    );
    await expect(
      sut.execute({ email: 'user@mail.com', password: 'pwd' }),
    ).rejects.toThrow(/RandomGenerator returned empty byte array/i);
  });
});
