import { RefreshToken } from '@/domain/auth/entities/refresh-token.entity';

describe('RefreshToken Entity', () => {
  const fixedDate = new Date('2024-01-01T00:00:00.000Z');
  const laterDate = new Date('2024-01-02T00:00:00.000Z');

  it('creates a new refresh token with default values', () => {
    const token = RefreshToken.create({
      id: 'rt-1',
      userId: 'user-1',
      secretHash: 'hashed-secret',
      familyId: 'family-1',
      createdAt: fixedDate,
      expiresAt: laterDate,
      createdByIp: '127.0.0.1',
      userAgent: 'jest-test',
    });
    expect(token.id).toBe('rt-1');
    expect(token.userId).toBe('user-1');
    expect(token.familyId).toBe('family-1');
    expect(token.secretHash).toBe('hashed-secret');
    expect(token.createdAt).toEqual(fixedDate);
    expect(token.expiresAt).toEqual(laterDate);
    expect(token.revokedAt).toBeNull();
    expect(token.replacedByTokenId).toBeNull();
    expect(token.createdByIp).toBe('127.0.0.1');
    expect(token.userAgent).toBe('jest-test');
    expect(token.lastUsedAt).toBeNull();
  });

  it('rehydrates from persistence without altering values', () => {
    const token = RefreshToken.rehydrate({
      id: 'rt-2',
      userId: 'user-2',
      secretHash: 'hashed',
      familyId: 'fam-2',
      createdAt: fixedDate,
      expiresAt: laterDate,
      revokedAt: fixedDate,
      replacedByTokenId: 'rt-3',
      createdByIp: '10.0.0.1',
      userAgent: 'chrome',
      lastUsedAt: laterDate,
    });
    expect(token.id).toBe('rt-2');
    expect(token.revokedAt).toEqual(fixedDate);
    expect(token.replacedByTokenId).toBe('rt-3');
    expect(token.lastUsedAt).toEqual(laterDate);
  });

  it('detects expiration correctly', () => {
    const createdAt = new Date('2023-12-31T23:59:00.000Z');
    const expiresAt = new Date('2024-01-01T00:00:00.000Z');
    const token = RefreshToken.create({
      id: 'rt-3',
      userId: 'user-3',
      secretHash: 'hash',
      familyId: 'fam-3',
      createdAt,
      expiresAt,
    });
    expect(token.isExpired(expiresAt)).toBe(true);
    expect(token.isExpired(new Date(expiresAt.getTime() - 1))).toBe(false);
  });

  it('revokes a token', () => {
    const token = RefreshToken.create({
      id: 'rt-4',
      userId: 'user-4',
      secretHash: 'hash',
      familyId: 'fam-4',
      createdAt: fixedDate,
      expiresAt: laterDate,
    });
    token.revoke(laterDate);
    expect(token.revokedAt).toEqual(laterDate);
    expect(token.isRevoked()).toBe(true);
  });

  it('replaces a token during rotation', () => {
    const token = RefreshToken.create({
      id: 'rt-5',
      userId: 'user-5',
      secretHash: 'hash',
      familyId: 'fam-5',
      createdAt: fixedDate,
      expiresAt: laterDate,
    });
    const nowBeforeExpiry = new Date(laterDate.getTime() - 1);
    token.replaceWith('rt-6', nowBeforeExpiry);
    expect(token.revokedAt).toEqual(nowBeforeExpiry);
    expect(token.replacedByTokenId).toBe('rt-6');
  });

  it('marks token as used', () => {
    const token = RefreshToken.create({
      id: 'rt-7',
      userId: 'user-7',
      secretHash: 'hash',
      familyId: 'fam-7',
      createdAt: fixedDate,
      expiresAt: laterDate,
    });
    token.markUsed(laterDate);
    expect(token.lastUsedAt).toEqual(laterDate);
  });

  it('toObject does not expose secretHash', () => {
    const token = RefreshToken.create({
      id: 'rt-8',
      userId: 'user-8',
      secretHash: 'super-secret-hash',
      familyId: 'fam-8',
      createdAt: fixedDate,
      expiresAt: laterDate,
    });
    const obj = token.toObject();
    expect(obj).toEqual({
      id: 'rt-8',
      userId: 'user-8',
      familyId: 'fam-8',
      createdAt: fixedDate,
      expiresAt: laterDate,
      revokedAt: null,
      replacedByTokenId: null,
    });
    // @ts-expect-error secretHash não deve aparecer
    expect(obj.secretHash).toBeUndefined();
  });

  it('throws when expiresAt <= createdAt or fields are empty', () => {
    const t = new Date('2024-01-01T00:00:00.000Z');
    expect(() =>
      RefreshToken.create({
        id: 'rt',
        userId: 'u',
        secretHash: 'h',
        familyId: 'fam',
        createdAt: t,
        expiresAt: t,
      }),
    ).toThrow(/expiresAt must be strictly greater than createdAt/i);
    expect(() =>
      RefreshToken.create({
        id: ' ',
        userId: 'u',
        secretHash: 'h',
        familyId: 'fam',
        createdAt: new Date(t),
        expiresAt: new Date(t.getTime() + 1000),
      }),
    ).toThrow(/RefreshToken\.id must be a non-empty string/i);
  });

  it('replaceWith throws if token is expired or revoked', () => {
    const createdAt = new Date('2024-01-01T00:00:00.000Z');
    const expiresAt = new Date('2024-01-01T00:05:00.000Z');
    const after = new Date('2024-01-01T00:06:00.000Z');
    const t = RefreshToken.create({
      id: 'rt-x',
      userId: 'u-x',
      secretHash: 'h',
      familyId: 'f-x',
      createdAt,
      expiresAt,
    });
    expect(() => t.replaceWith('rt-new', after)).toThrow(/expired/i);
    const t2 = RefreshToken.create({
      id: 'rt-y',
      userId: 'u-y',
      secretHash: 'h',
      familyId: 'f-y',
      createdAt,
      expiresAt,
    });
    const justBefore = new Date(expiresAt.getTime() - 1);
    t2.revoke(justBefore);
    expect(() => t2.replaceWith('rt-new', justBefore)).toThrow(/revoked/i);
  });

  it('revoke is idempotent and replaceWith prevents multiple replacement chains', () => {
    const createdAt = new Date('2024-01-01T00:00:00.000Z');
    const expiresAt = new Date('2024-01-01T00:05:00.000Z');
    const now = new Date('2024-01-01T00:01:00.000Z');
    const t = RefreshToken.create({
      id: 'rt-z',
      userId: 'u-z',
      secretHash: 'h',
      familyId: 'f-z',
      createdAt,
      expiresAt,
    });
    t.revoke(now);
    t.revoke(now);
    expect(t.revokedAt).toEqual(now);

    const t2 = RefreshToken.create({
      id: 'rt-a',
      userId: 'u-a',
      secretHash: 'h',
      familyId: 'f-a',
      createdAt,
      expiresAt,
    });
    t2.replaceWith('rt-b', now);
    expect(() => t2.replaceWith('rt-c', now)).toThrow(/already been replaced/i);
  });

  it('isActive works as expected across the token lifecycle', () => {
    const createdAt = new Date('2024-01-01T00:00:00.000Z');
    const expiresAt = new Date('2024-01-01T00:10:00.000Z');
    const t = RefreshToken.create({
      id: 'rt-active',
      userId: 'u',
      secretHash: 'h',
      familyId: 'f',
      createdAt,
      expiresAt,
    });
    const t1 = new Date('2024-01-01T00:05:00.000Z');
    expect(t.isActive(t1)).toBe(true);
    const t2 = new Date('2024-01-01T00:10:00.000Z');
    expect(t.isActive(t2)).toBe(false);
    const t3 = new Date('2024-01-01T00:01:00.000Z');
    t.revoke(t3);
    expect(t.isActive(t3)).toBe(false);
  });
});
