import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Request } from 'express';

@Injectable()
export class SameSiteGuard implements CanActivate {
  private readonly allowedOrigins: Set<string>;

  constructor(private readonly cfg: ConfigService) {
    const raw = (this.cfg.get<string>('CORS_ORIGIN') || '').trim();
    this.allowedOrigins = new Set(
      raw
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean),
    );
  }

  canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest<Request>();
    const origin = this.first(req.headers.origin);
    const referer = this.first(req.headers.referer);
    if (!origin && !referer) return true;
    if (this.allowedOrigins.size === 0) return true;
    const candidate = this.extractOrigin(origin, referer);
    if (!candidate) return true; // não conseguiu extrair → permite
    if (this.allowedOrigins.has(candidate)) return true;
    throw new ForbiddenException('Cross-site request blocked by SameSiteGuard');
  }

  private first(v: string | string[] | undefined): string | undefined {
    return Array.isArray(v) ? v[0] : v;
  }

  private extractOrigin(
    originHeader?: string,
    refererHeader?: string,
  ): string | null {
    const normOrigin = originHeader ? this.normalizeOrigin(originHeader) : null;
    if (normOrigin) return normOrigin;
    if (refererHeader) {
      try {
        const u = new URL(refererHeader);
        return `${u.protocol}//${u.host}`;
      } catch {
        /* ignore referer inválido */
      }
    }
    return null;
  }

  private normalizeOrigin(value: string): string | null {
    try {
      const u = new URL(value);
      if ((u.protocol === 'https:' || u.protocol === 'http:') && u.host) {
        return `${u.protocol}//${u.host}`;
      }
      return null;
    } catch {
      return null;
    }
  }
}
