import {
  Body,
  Controller,
  Post,
  Req,
  Res,
  HttpCode,
  HttpStatus,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { z } from 'zod';
import { AuthenticateUserUseCase } from '@domain/auth/use-cases/authenticate-user.use-case';
import { RotateRefreshTokenUseCase } from '@domain/auth/use-cases/rotate-refresh-token.use-case';
import { LogoutUseCase } from '@domain/auth/use-cases/logout.use-case';
import { ZodValidationPipe } from '@/app/http/validation/zod-validation.pipe';
import { ConfigService } from '@nestjs/config';
import { SameSiteGuard } from '@/app/common/guards/same-site.guard';

const authenticateSchema = z.object({
  email: z.email(),
  password: z.string().min(6),
});

function getUserAgent(value: unknown): string | null {
  if (typeof value === 'string') return value;
  if (Array.isArray(value) && value.every((v) => typeof v === 'string')) {
    return value[0] ?? null;
  }
  return null;
}

function getCookie(req: Request, name: string): string | undefined {
  const cookiesUnknown: unknown = (req as unknown as { cookies?: unknown })
    .cookies;
  if (cookiesUnknown && typeof cookiesUnknown === 'object') {
    const val = (cookiesUnknown as Record<string, unknown>)[name];
    if (typeof val === 'string') return val;
  }
  return undefined;
}

type SameSiteOpt = 'lax' | 'strict' | 'none';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authenticateUser: AuthenticateUserUseCase,
    private readonly rotateRefresh: RotateRefreshTokenUseCase,
    private readonly logoutUseCase: LogoutUseCase,
    private readonly cfg: ConfigService,
  ) {}

  private cookieOpts() {
    const cookieName = this.cfg.get<string>(
      'REFRESH_COOKIE_NAME',
      'refreshToken',
    );
    const ttlMs = Number(this.cfg.get('REFRESH_TOKEN_TTL_MS', '604800000')); // 7d
    const domain = this.cfg.get<string | undefined>('REFRESH_COOKIE_DOMAIN');
    const sameSiteCfg = (
      this.cfg.get<string>('REFRESH_COOKIE_SAMESITE', 'lax') || 'lax'
    ).toLowerCase() as SameSiteOpt;
    const secureFromEnv =
      this.cfg.get('REFRESH_COOKIE_SECURE', 'false') === 'true';
    const isSecure = sameSiteCfg === 'none' ? true : secureFromEnv;
    return {
      cookieName,
      opts: {
        httpOnly: true,
        sameSite: sameSiteCfg,
        secure: isSecure,
        domain: domain || undefined,
        path: '/',
        maxAge: ttlMs,
      } as const,
    };
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(
    @Body(new ZodValidationPipe(authenticateSchema))
    body: z.infer<typeof authenticateSchema>,
    @Res({ passthrough: true }) res: Response,
    @Req() req: Request,
  ) {
    const userAgent = getUserAgent(req.headers['user-agent']);
    const result = await this.authenticateUser.execute({
      email: body.email,
      password: body.password,
      createdByIp: req.ip,
      userAgent,
    });
    const { cookieName, opts } = this.cookieOpts();
    res.cookie(cookieName, result.refreshToken, opts);
    res.setHeader('Authorization', `Bearer ${result.accessToken}`);
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Vary', 'Origin, Cookie');
    return { user: result.user };
  }

  @Post('refresh')
  @UseGuards(SameSiteGuard)
  @HttpCode(HttpStatus.OK)
  async refresh(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const cookieName = this.cfg.get<string>(
      'REFRESH_COOKIE_NAME',
      'refreshToken',
    );
    const raw = getCookie(req, cookieName);
    if (!raw) {
      throw new UnauthorizedException('Missing refresh token');
    }
    const out = await this.rotateRefresh.execute({ refreshToken: raw });
    const { cookieName: name, opts } = this.cookieOpts();
    res.cookie(name, out.refreshToken, opts);
    res.setHeader('Authorization', `Bearer ${out.accessToken}`);
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Vary', 'Origin, Cookie');
    return { ok: true };
  }

  @Post('logout')
  @UseGuards(SameSiteGuard)
  @HttpCode(HttpStatus.OK)
  async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const { cookieName, opts } = this.cookieOpts();
    const raw = getCookie(req, cookieName);
    if (raw) {
      await this.logoutUseCase.execute({ refreshToken: raw });
    }
    res.clearCookie(cookieName, { ...opts, maxAge: undefined });
    return { ok: true };
  }
}
