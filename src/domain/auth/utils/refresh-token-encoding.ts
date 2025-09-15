import { InvariantViolationError } from '@domain/shared/errors/invariant-violation.error';

function isNonEmpty(s: string | null | undefined): s is string {
  return typeof s === 'string' && s.trim().length > 0;
}

export function encodeRefreshToken(
  id: string,
  secretBase64url: string,
): string {
  if (!isNonEmpty(id)) {
    throw new InvariantViolationError('id must be a non-empty string');
  }
  if (!isNonEmpty(secretBase64url)) {
    throw new InvariantViolationError(
      'secretBase64url must be a non-empty string',
    );
  }
  return `${id}.${secretBase64url}`;
}

export function decodeRefreshToken(
  token: string,
): { id: string; secretBase64url: string } | null {
  if (!isNonEmpty(token)) return null;
  const dot = token.indexOf('.');
  if (dot <= 0 || dot === token.length - 1) return null;
  const id = token.slice(0, dot);
  const secretBase64url = token.slice(dot + 1);
  if (!isNonEmpty(id) || !isNonEmpty(secretBase64url)) return null;
  return { id, secretBase64url };
}
