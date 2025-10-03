import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TokenSigner } from '@domain/auth/services/token-signer';
import {
  JwtTokenSignerService,
  createJwtTokenSigner,
} from './jwt-token-signer.service';

type HsAlgorithm = 'HS256' | 'HS384' | 'HS512';

@Module({
  imports: [ConfigModule],
  providers: [
    {
      provide: JwtTokenSignerService,
      inject: [ConfigService],
      useFactory: (cfg: ConfigService) => {
        const secret = cfg.get<string>('JWT_ACCESS_TOKEN_SECRET');
        if (!secret) {
          throw new Error('JWT_ACCESS_TOKEN_SECRET is not configured');
        }
        const rawAlg = (
          cfg.get<string>('ACCESS_TOKEN_ALG') ??
          cfg.get<string>('JWT_ACCESS_ALG') ??
          'HS256'
        ).toUpperCase();
        const allowed = ['HS256', 'HS384', 'HS512'] as const;
        const alg: HsAlgorithm = (allowed as readonly string[]).includes(rawAlg)
          ? (rawAlg as HsAlgorithm)
          : 'HS256';
        return createJwtTokenSigner(secret, alg);
      },
    },
    { provide: TokenSigner, useExisting: JwtTokenSignerService },
  ],
  exports: [TokenSigner],
})
export class JwtModule {}
