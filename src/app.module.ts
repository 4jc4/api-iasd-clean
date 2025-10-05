import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { EnvModule } from '@/app/config/env.module';
import { AuthController } from '@app/http/auth/auth.controller';
import { UsersController } from '@app/http/users/users.controller';
import { HealthController } from '@app/http/health/health.controller';
import { PrismaService } from '@infra/database/prisma/prisma.service';
import { PrismaUserRepository } from '@infra/database/prisma/repositories/prisma-user.repository';
import { PrismaRefreshTokenRepository } from '@infra/database/prisma/repositories/prisma-refresh-token.repository';
import { Argon2HashService } from '@infra/hash/argon2-hash.service';
import { UuidService } from '@infra/uuid/uuid.service';
import { SystemClock } from '@infra/clock/system-clock.service';
import { CryptoRandomService } from '@infra/random/crypto-random.service';
import { JwtModule } from '@infra/auth/jwt/jwt.module';
import { UserRepository } from '@domain/users/repositories/user.repository';
import { RefreshTokenRepository } from '@domain/auth/repositories/refresh-token.repository';
import { HashGenerator } from '@domain/shared/services/hash-generator';
import { UuidGenerator } from '@domain/shared/services/uuid-generator';
import { Clock } from '@domain/shared/services/clock';
import { RandomGenerator } from '@domain/shared/services/random-generator';
import { TokenSigner } from '@domain/auth/services/token-signer';
import { AuthenticateUserUseCase } from '@domain/auth/use-cases/authenticate-user.use-case';
import { RotateRefreshTokenUseCase } from '@domain/auth/use-cases/rotate-refresh-token.use-case';
import { LogoutUseCase } from '@domain/auth/use-cases/logout.use-case';
import { CreateUserUseCase } from '@domain/users/use-cases/create-user.use-case';
import { JwtAuthGuard } from '@app/http/auth/jwt-auth.guard';
import { RolesGuard } from '@app/http/auth/roles.guard';
import { SameSiteGuard } from '@app/common/guards/same-site.guard';

@Module({
  imports: [EnvModule, JwtModule],
  controllers: [AuthController, UsersController, HealthController],
  providers: [
    PrismaService,
    { provide: UserRepository, useClass: PrismaUserRepository },
    { provide: RefreshTokenRepository, useClass: PrismaRefreshTokenRepository },
    { provide: HashGenerator, useClass: Argon2HashService },
    { provide: UuidGenerator, useClass: UuidService },
    { provide: Clock, useClass: SystemClock },
    { provide: RandomGenerator, useClass: CryptoRandomService },
    {
      provide: AuthenticateUserUseCase,
      inject: [
        UserRepository,
        RefreshTokenRepository,
        HashGenerator,
        RandomGenerator,
        UuidGenerator,
        Clock,
        TokenSigner,
        ConfigService,
      ],
      useFactory: (
        users: UserRepository,
        refreshTokens: RefreshTokenRepository,
        hash: HashGenerator,
        random: RandomGenerator,
        uuid: UuidGenerator,
        clock: Clock,
        tokenSigner: TokenSigner,
        cfg: ConfigService,
      ) =>
        new AuthenticateUserUseCase(
          users,
          refreshTokens,
          hash,
          random,
          uuid,
          clock,
          tokenSigner,
          {
            accessTokenTtl: cfg.get<string>('ACCESS_TOKEN_TTL', '15m'),
            refreshTokenTtlMs: Number(
              cfg.get<string>('REFRESH_TOKEN_TTL_MS', '604800000'),
            ),
            refreshSecretBytes: Number(
              cfg.get<string>('REFRESH_SECRET_BYTES', '32'),
            ),
          },
        ),
    },
    {
      provide: RotateRefreshTokenUseCase,
      inject: [
        RefreshTokenRepository,
        UserRepository,
        HashGenerator,
        UuidGenerator,
        Clock,
        RandomGenerator,
        TokenSigner,
        ConfigService,
      ],
      useFactory: (
        refreshTokens: RefreshTokenRepository,
        users: UserRepository,
        hash: HashGenerator,
        uuid: UuidGenerator,
        clock: Clock,
        random: RandomGenerator,
        tokenSigner: TokenSigner,
        cfg: ConfigService,
      ) =>
        new RotateRefreshTokenUseCase(
          refreshTokens,
          users,
          hash,
          uuid,
          clock,
          random,
          tokenSigner,
          {
            accessTokenTtl: cfg.get<string>('ACCESS_TOKEN_TTL', '15m'),
            refreshTokenTtlMs: Number(
              cfg.get<string>('REFRESH_TOKEN_TTL_MS', '604800000'),
            ),
            refreshSecretBytes: Number(
              cfg.get<string>('REFRESH_SECRET_BYTES', '32'),
            ),
          },
        ),
    },
    {
      provide: LogoutUseCase,
      inject: [RefreshTokenRepository, Clock],
      useFactory: (refreshTokens: RefreshTokenRepository, clock: Clock) =>
        new LogoutUseCase(refreshTokens, clock),
    },
    {
      provide: CreateUserUseCase,
      inject: [UserRepository, HashGenerator, UuidGenerator, Clock],
      useFactory: (
        users: UserRepository,
        hash: HashGenerator,
        uuid: UuidGenerator,
        clock: Clock,
      ) => new CreateUserUseCase(users, hash, uuid, clock),
    },
    JwtAuthGuard,
    RolesGuard,
    SameSiteGuard,
  ],
})
export class AppModule {}
