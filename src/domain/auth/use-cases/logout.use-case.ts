import { RefreshTokenRepository } from '@domain/auth/repositories/refresh-token.repository';
import { decodeRefreshToken } from '@domain/auth/utils/refresh-token-encoding';
import { RefreshTokenNotFoundError } from '@domain/auth/errors/auth.errors';
import { Clock } from '@domain/shared/services/clock';

export interface LogoutInput {
  refreshToken: string;
}

export class LogoutUseCase {
  constructor(
    private readonly refreshTokens: RefreshTokenRepository,
    private readonly clock: Clock,
  ) {}

  async execute(input: LogoutInput): Promise<void> {
    const parsed = decodeRefreshToken(input.refreshToken);
    if (!parsed) throw new RefreshTokenNotFoundError();
    const found = await this.refreshTokens.findById(parsed.id);
    if (!found) throw new RefreshTokenNotFoundError();
    await this.refreshTokens.revokeFamily(
      found.userId,
      found.familyId,
      this.clock.now(),
    );
  }
}
