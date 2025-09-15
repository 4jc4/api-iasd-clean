import { Role } from '@domain/users/enums/role.enum';
import {
  InvalidEmailError,
  InvalidNameError,
  InvalidRoleError,
} from '@domain/users/errors/user.errors';
import { normalizeEmail, isEmailValid } from '@domain/shared/utils/email';

export class User {
  private constructor(
    private readonly _id: string,
    private readonly _email: string,
    private readonly _name: string,
    private readonly _role: Role,
    private readonly _passwordHash: string,
    private readonly _createdAt: Date,
    private readonly _updatedAt: Date,
  ) {}

  static create(
    params: {
      email: string;
      name: string;
      passwordHash: string;
      role?: Role;
    },
    deps: { uuid: () => string; now: () => Date },
  ): User {
    const email = normalizeEmail(params.email);
    if (!email || !isEmailValid(email)) {
      throw new InvalidEmailError();
    }
    const name = params.name.trim();
    if (!name) {
      throw new InvalidNameError();
    }
    const role = params.role ?? Role.USER;
    if (!Object.values(Role).includes(role)) {
      throw new InvalidRoleError(role as unknown as string);
    }
    const now = deps.now();
    return new User(
      deps.uuid(),
      email,
      name,
      role,
      params.passwordHash,
      now,
      now,
    );
  }

  static rehydrate(params: {
    id: string;
    email: string;
    name: string;
    passwordHash: string;
    role: Role;
    createdAt: Date;
    updatedAt: Date;
  }): User {
    const email = normalizeEmail(params.email);
    if (!email || !isEmailValid(email)) {
      throw new InvalidEmailError();
    }
    const name = params.name.trim();
    if (!name) {
      throw new InvalidNameError();
    }
    if (!Object.values(Role).includes(params.role)) {
      throw new InvalidRoleError(params.role as unknown as string);
    }
    return new User(
      params.id,
      email,
      name,
      params.role,
      params.passwordHash,
      params.createdAt,
      params.updatedAt,
    );
  }

  get id(): string {
    return this._id;
  }
  get email(): string {
    return this._email;
  }
  get name(): string {
    return this._name;
  }
  get role(): Role {
    return this._role;
  }
  get createdAt(): Date {
    return this._createdAt;
  }
  get updatedAt(): Date {
    return this._updatedAt;
  }
  get passwordHash(): string {
    return this._passwordHash;
  }

  toObject(): {
    id: string;
    email: string;
    name: string;
    role: Role;
    createdAt: Date;
    updatedAt: Date;
  } {
    return {
      id: this._id,
      email: this._email,
      name: this._name,
      role: this._role,
      createdAt: this._createdAt,
      updatedAt: this._updatedAt,
    };
  }

  toJSON() {
    return this.toObject();
  }
}
