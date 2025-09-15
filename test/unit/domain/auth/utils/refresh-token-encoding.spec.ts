import {
  decodeRefreshToken,
  encodeRefreshToken,
} from '@/domain/auth/utils/refresh-token-encoding';

describe('refresh-token-encoding', () => {
  it('encodes and decodes token correctly', () => {
    const token = encodeRefreshToken('id-123', 'secret-xyz');
    expect(token).toBe('id-123.secret-xyz');
    const parsed = decodeRefreshToken(token);
    expect(parsed).toEqual({ id: 'id-123', secretBase64url: 'secret-xyz' });
  });

  it('returns null for invalid formats', () => {
    expect(decodeRefreshToken('')).toBeNull();
    expect(decodeRefreshToken('no-dot')).toBeNull();
    expect(decodeRefreshToken('.secret')).toBeNull();
    expect(decodeRefreshToken('id.')).toBeNull();
  });
});
