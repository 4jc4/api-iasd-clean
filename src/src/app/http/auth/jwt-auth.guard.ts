import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import type { Request } from 'express';
import {
  TokenSigner,
  isAccessTokenPayload,
} from '@domain/auth/services/token-signer';

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(private readonly tokenSigner: TokenSigner) {}

  canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest<Request>();
    const header = req.headers['authorization'];
    if (!header || Array.isArray(header)) {
      throw new UnauthorizedException('Missing Authorization header');
    }
    const [scheme, token] = header.split(' ');
    if (scheme !== 'Bearer' || !token) {
      throw new UnauthorizedException('Invalid Authorization header');
    }
    const payload = this.tokenSigner.verifyAccessToken(token);
    if (!payload || !isAccessTokenPayload(payload)) {
      throw new UnauthorizedException('Invalid or expired access token');
    }
    req.user = { sub: payload.sub, role: payload.role };
    return true;
  }
}
