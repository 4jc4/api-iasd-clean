import { RefreshTokenRepository } from '@domain/auth/repositories/refresh-token.repository';
import {
  RefreshTokenExpiredError,
  RefreshTokenNotFoundError,
  RefreshTokenReuseDetectedError,
  RefreshTokenRevokedError,
} from '@domain/auth/errors/auth.errors';
import {
  decodeRefreshToken,
  encodeRefreshToken,
} from '@domain/auth/utils/refresh-token-encoding';
import { HashGenerator } from '@domain/shared/services/hash-generator';
import { UuidGenerator } from '@domain/shared/services/uuid-generator';
import { Clock } from '@domain/shared/services/clock';
import { RandomGenerator } from '@domain/shared/services/random-generator';
import { TokenSigner } from '@domain/auth/services/token-signer';
import { UserRepository } from '@domain/users/repositories/user.repository';
import { RefreshInput } from '@domain/auth/use-cases/dto/refresh-input';
import { RefreshOutput } from '@domain/auth/use-cases/dto/refresh-output';
import { RefreshToken } from '@domain/auth/entities/refresh-token.entity';
import { InvariantViolationError } from '@domain/shared/errors/invariant-violation.error';

type RotationConfig = {
  accessTokenTtl: string; // ex: '15m'
  refreshTokenTtlMs: number; // ex: 7d em ms
  refreshSecretBytes?: number; // ex: 32
};

export class RotateRefreshTokenUseCase {
  constructor(
    private readonly refreshTokens: RefreshTokenRepository,
    private readonly users: UserRepository,
    private readonly hash: HashGenerator,
    private readonly uuid: UuidGenerator,
    private readonly clock: Clock,
    private readonly random: RandomGenerator,
    private readonly tokenSigner: TokenSigner,
    private readonly config: RotationConfig,
  ) {}

  async execute(input: RefreshInput): Promise<RefreshOutput> {
    const parsed = decodeRefreshToken(input.refreshToken);
    if (!parsed) throw new RefreshTokenNotFoundError();
    const { id: presentedId, secretBase64url: presentedSecret } = parsed;
    const now = this.clock.now();
    const current = await this.refreshTokens.findById(presentedId);
    if (!current) throw new RefreshTokenNotFoundError();
    const matches = await this.hash.compare(
      presentedSecret,
      current.secretHash,
    );
    if (!matches) throw new RefreshTokenNotFoundError();
    if (current.isExpired(now)) throw new RefreshTokenExpiredError();
    if (current.isRevoked()) throw new RefreshTokenRevokedError();
    const latest = await this.refreshTokens.findLatestByFamily(
      current.userId,
      current.familyId,
    );
    if (latest && latest.id !== current.id) {
      await this.refreshTokens.revokeFamily(
        current.userId,
        current.familyId,
        now,
      );
      throw new RefreshTokenReuseDetectedError();
    }
    const user = await this.users.findById(current.userId);
    if (!user) {
      throw new InvariantViolationError(
        'Invariant violation: user not found for refresh token',
      );
    }
    current.markUsed(now);
    const newId = this.uuid.generate();
    const byteLen = this.config.refreshSecretBytes ?? 32;
    const secretBytes = await this.random.randomBytes(byteLen);
    if (!secretBytes || secretBytes.length < 1) {
      throw new InvariantViolationError(
        'RandomGenerator returned empty byte array',
      );
    }
    const newSecretBase64url = this.random.toBase64url(secretBytes);
    const newSecretHash = await this.hash.hash(newSecretBase64url);
    const newExpiresAt = new Date(
      now.getTime() + this.config.refreshTokenTtlMs,
    );
    current.replaceWith(newId, now);
    const next = RefreshToken.create({
      id: newId,
      userId: current.userId,
      secretHash: newSecretHash,
      familyId: current.familyId,
      createdAt: now,
      expiresAt: newExpiresAt,
    });
    await this.refreshTokens.replaceAndInsertAtomic(current, next);
    const accessToken = this.tokenSigner.signAccessToken(
      { sub: user.id, role: user.role },
      { expiresIn: this.config.accessTokenTtl },
    );
    const refreshToken = encodeRefreshToken(newId, newSecretBase64url);
    return { accessToken, refreshToken };
  }
}
