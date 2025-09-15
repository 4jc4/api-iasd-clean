import { DomainError } from '@domain/shared/errors/domain-error';

export class EmailAlreadyInUseError extends DomainError {
  constructor(email: string) {
    super(`Email "${email}" is already in use.`);
  }
}

export class UnauthorizedUserError extends DomainError {
  constructor(action: string = 'perform this action') {
    super(`User is not authorized to ${action}.`);
  }
}

export class UserNotFoundError extends DomainError {
  constructor(identifier: string) {
    super(`User with identifier "${identifier}" not found.`);
  }
}

export class InvalidEmailError extends DomainError {
  constructor() {
    super('Email cannot be empty or invalid');
  }
}

export class InvalidNameError extends DomainError {
  constructor() {
    super('Name cannot be empty');
  }
}

export class InvalidRoleError extends DomainError {
  constructor(role: string) {
    super(`Invalid role: ${role}`);
  }
}
