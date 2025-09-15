import {
  RefreshTokenExpiredError,
  RefreshTokenRevokedError,
} from '@domain/auth/errors/auth.errors';
import { InvariantViolationError } from '@domain/shared/errors/invariant-violation.error';

function isNonEmpty(value: string | null | undefined): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

export class RefreshToken {
  private constructor(
    private readonly _id: string,
    private readonly _userId: string,
    private readonly _secretHash: string,
    private readonly _familyId: string,
    private readonly _createdAt: Date,
    private readonly _expiresAt: Date,
    private _revokedAt: Date | null,
    private _replacedByTokenId: string | null,
    private readonly _createdByIp?: string | null,
    private readonly _userAgent?: string | null,
    private _lastUsedAt?: Date | null,
  ) {
    if (!isNonEmpty(_id))
      throw new InvariantViolationError(
        'RefreshToken.id must be a non-empty string',
      );
    if (!isNonEmpty(_userId))
      throw new InvariantViolationError(
        'RefreshToken.userId must be a non-empty string',
      );
    if (!isNonEmpty(_secretHash))
      throw new InvariantViolationError(
        'RefreshToken.secretHash must be a non-empty string',
      );
    if (!isNonEmpty(_familyId))
      throw new InvariantViolationError(
        'RefreshToken.familyId must be a non-empty string',
      );
    if (!(_createdAt instanceof Date) || Number.isNaN(_createdAt.getTime())) {
      throw new InvariantViolationError(
        'RefreshToken.createdAt must be a valid Date',
      );
    }
    if (!(_expiresAt instanceof Date) || Number.isNaN(_expiresAt.getTime())) {
      throw new InvariantViolationError(
        'RefreshToken.expiresAt must be a valid Date',
      );
    }
    if (_expiresAt <= _createdAt) {
      throw new InvariantViolationError(
        'RefreshToken.expiresAt must be strictly greater than createdAt',
      );
    }
    if (this._lastUsedAt && this._lastUsedAt < this._createdAt) {
      throw new InvariantViolationError(
        'RefreshToken.lastUsedAt cannot be before createdAt',
      );
    }
  }

  static create(params: {
    id: string;
    userId: string;
    secretHash: string;
    familyId: string;
    createdAt: Date;
    expiresAt: Date;
    createdByIp?: string | null;
    userAgent?: string | null;
  }): RefreshToken {
    return new RefreshToken(
      params.id,
      params.userId,
      params.secretHash,
      params.familyId,
      params.createdAt,
      params.expiresAt,
      null,
      null,
      params.createdByIp ?? null,
      params.userAgent ?? null,
      null,
    );
  }

  static rehydrate(params: {
    id: string;
    userId: string;
    secretHash: string;
    familyId: string;
    createdAt: Date;
    expiresAt: Date;
    revokedAt: Date | null;
    replacedByTokenId: string | null;
    createdByIp?: string | null;
    userAgent?: string | null;
    lastUsedAt?: Date | null;
  }): RefreshToken {
    return new RefreshToken(
      params.id,
      params.userId,
      params.secretHash,
      params.familyId,
      params.createdAt,
      params.expiresAt,
      params.revokedAt,
      params.replacedByTokenId,
      params.createdByIp ?? null,
      params.userAgent ?? null,
      params.lastUsedAt ?? null,
    );
  }

  get id() {
    return this._id;
  }

  get userId() {
    return this._userId;
  }

  get familyId() {
    return this._familyId;
  }

  get secretHash() {
    return this._secretHash;
  }

  get createdAt() {
    return this._createdAt;
  }

  get expiresAt() {
    return this._expiresAt;
  }

  get revokedAt() {
    return this._revokedAt;
  }

  get replacedByTokenId() {
    return this._replacedByTokenId;
  }

  get createdByIp(): string | null | undefined {
    return this._createdByIp;
  }

  get userAgent(): string | null | undefined {
    return this._userAgent;
  }

  get lastUsedAt(): Date | null | undefined {
    return this._lastUsedAt;
  }

  isExpired(now: Date) {
    return now >= this._expiresAt;
  }

  isRevoked() {
    return !!this._revokedAt;
  }

  isActive(now: Date) {
    return !this.isRevoked() && !this.isExpired(now);
  }

  markUsed(now: Date) {
    if (this._lastUsedAt && now < this._lastUsedAt) return;
    this._lastUsedAt = now;
  }

  revoke(now: Date) {
    if (this._revokedAt) {
      return;
    }
    this._revokedAt = now;
  }

  replaceWith(newTokenId: string, now: Date) {
    if (!isNonEmpty(newTokenId)) {
      throw new InvariantViolationError(
        'newTokenId must be a non-empty string',
      );
    }
    if (this._replacedByTokenId) {
      if (this._replacedByTokenId === newTokenId) {
        return;
      }
      throw new InvariantViolationError(
        'Refresh token has already been replaced by another token.',
      );
    }
    if (this.isExpired(now)) {
      throw new RefreshTokenExpiredError();
    }
    if (this.isRevoked()) {
      throw new RefreshTokenRevokedError();
    }
    this._revokedAt = now;
    this._replacedByTokenId = newTokenId;
  }

  toObject() {
    return {
      id: this._id,
      userId: this._userId,
      familyId: this._familyId,
      createdAt: this._createdAt,
      expiresAt: this._expiresAt,
      revokedAt: this._revokedAt,
      replacedByTokenId: this._replacedByTokenId,
    };
  }
}
