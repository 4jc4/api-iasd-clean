import { Role } from '@domain/users/enums/role.enum';

export type AccessTokenPayload = { sub: string; role: Role };

export function isAccessTokenPayload(x: unknown): x is AccessTokenPayload {
  if (x == null || typeof x !== 'object') return false;
  if (!('sub' in x) || !('role' in x)) return false;
  const maybe = x as Record<string, unknown>;
  return (
    typeof maybe.sub === 'string' &&
    typeof maybe.role === 'string' &&
    Object.values(Role).includes(maybe.role as Role)
  );
}

export abstract class TokenSigner {
  abstract signAccessToken(
    payload: AccessTokenPayload,
    opts: { expiresIn: string },
  ): string;
  abstract verifyAccessToken(token: string): AccessTokenPayload | null;
}
