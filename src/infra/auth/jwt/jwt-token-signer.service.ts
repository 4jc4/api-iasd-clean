import { Injectable } from '@nestjs/common';
import {
  TokenSigner,
  AccessTokenPayload,
  isAccessTokenPayload,
} from '@domain/auth/services/token-signer';
import {
  sign,
  verify,
  type SignOptions,
  type VerifyOptions,
  type JwtPayload,
  type Algorithm,
} from 'jsonwebtoken';

type HsAlgorithm = Extract<Algorithm, 'HS256' | 'HS384' | 'HS512'>;

type ExpiresIn = NonNullable<SignOptions['expiresIn']>;

interface JwtConfig {
  secret: string;
  algorithm?: HsAlgorithm;
}

@Injectable()
export class JwtTokenSignerService implements TokenSigner {
  private readonly secret: string;
  private readonly algorithm: HsAlgorithm;

  constructor(cfg: JwtConfig) {
    if (!cfg?.secret) {
      throw new Error('JWT_ACCESS_TOKEN_SECRET is not configured');
    }
    this.secret = cfg.secret;
    this.algorithm = cfg.algorithm ?? 'HS256';
  }

  private toExpiresIn(value: string): ExpiresIn {
    const v = value.trim();
    if (/^\d+(\.\d+)?$/.test(v)) return Number(v);
    return v as ExpiresIn;
  }

  signAccessToken(
    payload: AccessTokenPayload,
    opts: { expiresIn: string },
  ): string {
    const options: SignOptions = {
      algorithm: this.algorithm,
      expiresIn: this.toExpiresIn(opts.expiresIn),
    };
    return sign(payload as object, this.secret, options);
  }

  verifyAccessToken(token: string): AccessTokenPayload | null {
    try {
      const options: VerifyOptions = { algorithms: [this.algorithm] };
      const decoded = verify(token, this.secret, options) as
        | JwtPayload
        | string;
      return typeof decoded === 'object' &&
        decoded !== null &&
        isAccessTokenPayload(decoded)
        ? decoded
        : null;
    } catch {
      return null;
    }
  }
}

export const createJwtTokenSigner = (
  secret: string,
  algorithm: HsAlgorithm = 'HS256',
): JwtTokenSignerService => new JwtTokenSignerService({ secret, algorithm });
