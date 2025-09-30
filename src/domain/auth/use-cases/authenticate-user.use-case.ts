import { UserRepository } from '@domain/users/repositories/user.repository';
import { HashGenerator } from '@domain/shared/services/hash-generator';
import { RandomGenerator } from '@domain/shared/services/random-generator';
import { UuidGenerator } from '@domain/shared/services/uuid-generator';
import { Clock } from '@domain/shared/services/clock';
import { TokenSigner } from '@domain/auth/services/token-signer';
import { RefreshTokenRepository } from '@domain/auth/repositories/refresh-token.repository';
import { RefreshToken } from '@domain/auth/entities/refresh-token.entity';
import { InvalidCredentialsError } from '@domain/auth/errors/auth.errors';
import { encodeRefreshToken } from '@domain/auth/utils/refresh-token-encoding';
import { AuthenticateInput } from '@domain/auth/use-cases/dto/authenticate-user-input';
import { AuthenticateOutput } from '@domain/auth/use-cases/dto/authenticate-user-output';
import { InvariantViolationError } from '@domain/shared/errors/invariant-violation.error';
import { normalizeEmail } from '@domain/shared/utils/email';

type AuthConfig = {
  accessTokenTtl: string; // ex: '15m'
  refreshTokenTtlMs: number; // ex: 7 * 24 * 60 * 60 * 1000
  refreshSecretBytes?: number; // ex: 32
};

export class AuthenticateUserUseCase {
  constructor(
    private readonly users: UserRepository,
    private readonly refreshTokens: RefreshTokenRepository,
    private readonly hash: HashGenerator,
    private readonly random: RandomGenerator,
    private readonly uuid: UuidGenerator,
    private readonly clock: Clock,
    private readonly tokenSigner: TokenSigner,
    private readonly config: AuthConfig,
  ) {}

  async execute(input: AuthenticateInput): Promise<AuthenticateOutput> {
    const email = normalizeEmail(input.email);
    const user = await this.users.findByEmail(email);
    if (!user) throw new InvalidCredentialsError();
    const ok = await this.hash.compare(input.password, user.passwordHash);
    if (!ok) throw new InvalidCredentialsError();
    const now = this.clock.now();
    const familyId = this.uuid.generate();
    const byteLen = this.config.refreshSecretBytes ?? 32;
    const secretBytes = await this.random.randomBytes(byteLen);
    if (!secretBytes || secretBytes.length < 1) {
      throw new InvariantViolationError(
        'RandomGenerator returned empty byte array',
      );
    }
    const secretBase64url = this.random.toBase64url(secretBytes);
    const tokenId = this.uuid.generate();
    const secretHash = await this.hash.hash(secretBase64url);
    const expiresAt = new Date(now.getTime() + this.config.refreshTokenTtlMs);
    const rt = RefreshToken.create({
      id: tokenId,
      userId: user.id,
      secretHash,
      familyId,
      createdAt: now,
      expiresAt,
      createdByIp: input.createdByIp ?? null,
      userAgent: input.userAgent ?? null,
    });
    await this.refreshTokens.save(rt);
    const accessToken = this.tokenSigner.signAccessToken(
      { sub: user.id, role: user.role },
      { expiresIn: this.config.accessTokenTtl },
    );
    const refreshToken = encodeRefreshToken(tokenId, secretBase64url);
    return {
      accessToken,
      refreshToken,
      user: user.toObject(),
    };
  }
}
