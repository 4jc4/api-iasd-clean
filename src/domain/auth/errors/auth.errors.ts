import { DomainError } from '@domain/shared/errors/domain-error';

export class InvalidCredentialsError extends DomainError {
  constructor() {
    super('Invalid email or password.');
  }
}

export class RefreshTokenNotFoundError extends DomainError {
  constructor() {
    super('Refresh token not found.');
  }
}

export class RefreshTokenExpiredError extends DomainError {
  constructor() {
    super('Refresh token has expired.');
  }
}

export class RefreshTokenRevokedError extends DomainError {
  constructor() {
    super('Refresh token has been revoked.');
  }
}

export class RefreshTokenReuseDetectedError extends DomainError {
  constructor() {
    super('Refresh token reuse detected; family revoked.');
  }
}
