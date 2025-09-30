import { LogoutUseCase } from '@/domain/auth/use-cases/logout.use-case';
import { RefreshTokenRepository } from '@/domain/auth/repositories/refresh-token.repository';
import { Clock } from '@/domain/shared/services/clock';
import { RefreshToken } from '@/domain/auth/entities/refresh-token.entity';
import { RefreshTokenNotFoundError } from '@/domain/auth/errors/auth.errors';

describe('LogoutUseCase', () => {
  const createdAt = new Date('2024-01-01T00:00:00.000Z');
  const now = new Date('2024-01-02T00:00:00.000Z');
  const expiresAt = new Date('2024-01-08T00:00:00.000Z');

  const makeSut = () => {
    const repo: jest.Mocked<RefreshTokenRepository> = {
      findById: jest.fn(),
      save: jest.fn(),
      revokeFamily: jest.fn(),
      findLatestByFamily: jest.fn(),
      findActiveById: jest.fn(),
      replaceAndInsertAtomic: jest.fn().mockResolvedValue(undefined),
    };
    const clock: jest.Mocked<Clock> = {
      now: jest.fn().mockReturnValue(now),
    };
    const sut = new LogoutUseCase(repo, clock);
    return { sut, repo, clock };
  };

  it('revokes the entire token family when a valid token is presented', async () => {
    const { sut, repo, clock } = makeSut();
    const token = RefreshToken.rehydrate({
      id: 'rt-1',
      userId: 'u-1',
      secretHash: 'hash',
      familyId: 'fam-1',
      createdAt,
      expiresAt,
      revokedAt: null,
      replacedByTokenId: null,
      createdByIp: '127.0.0.1',
      userAgent: 'jest',
      lastUsedAt: null,
    });
    repo.findById.mockResolvedValue(token);
    await sut.execute({ refreshToken: 'rt-1.AQID' });
    expect(repo.findById).toHaveBeenCalledWith('rt-1');
    expect(repo.revokeFamily).toHaveBeenCalledWith('u-1', 'fam-1', clock.now());
  });

  it('throws when token id is not found or malformed', async () => {
    const { sut, repo } = makeSut();
    repo.findById.mockResolvedValue(null);
    await expect(
      sut.execute({ refreshToken: 'rt-missing.AQID' }),
    ).rejects.toThrow(RefreshTokenNotFoundError);
    await expect(sut.execute({ refreshToken: '' })).rejects.toThrow(
      RefreshTokenNotFoundError,
    );
    await expect(sut.execute({ refreshToken: 'no-dot' })).rejects.toThrow(
      RefreshTokenNotFoundError,
    );
  });
});
