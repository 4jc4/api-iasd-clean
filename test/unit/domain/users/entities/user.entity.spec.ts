import { User } from '@/domain/users/entities/user.entity';
import { Role } from '@/domain/users/enums/role.enum';
import {
  InvalidEmailError,
  InvalidNameError,
  InvalidRoleError,
} from '@/domain/users/errors/user.errors';

describe('User Entity', () => {
  const fixedDate = new Date('2024-01-01T00:00:00.000Z');
  const deps = {
    uuid: () => 'fixed-uuid',
    now: () => fixedDate,
  };

  it('creates a valid user normalizing email and name', () => {
    const user = User.create(
      {
        email: '  TEST@MAIL.COM  ',
        name: '  Alice  ',
        passwordHash: 'hash123',
      },
      deps,
    );
    expect(user.id).toBe('fixed-uuid');
    expect(user.email).toBe('test@mail.com');
    expect(user.name).toBe('Alice');
    expect(user.role).toBe(Role.USER);
    expect(user.createdAt).toEqual(fixedDate);
    expect(user.updatedAt).toEqual(fixedDate);
  });

  it('accepts an explicit valid role (ADMIN)', () => {
    const user = User.create(
      {
        email: 'admin@mail.com',
        name: 'Admin',
        passwordHash: 'hash',
        role: Role.ADMIN,
      },
      deps,
    );
    expect(user.role).toBe(Role.ADMIN);
  });

  it.each([
    { email: '   ', name: 'Alice', error: InvalidEmailError },
    { email: 'a@a.com', name: '   ', error: InvalidNameError },
  ])(
    'throws validation error: %#',
    ({
      email,
      name,
      error,
    }: {
      email: string;
      name: string;
      error: new () => Error;
    }) => {
      expect(() =>
        User.create({ email, name, passwordHash: 'hash' }, deps),
      ).toThrow(error);
    },
  );

  it('throws InvalidRoleError when role is invalid', () => {
    // @ts-expect-error testing invalid value
    const badRole: Role = 'SUPER_ADMIN';
    expect(() =>
      User.create(
        {
          email: 'a@a.com',
          name: 'Alice',
          passwordHash: 'hash',
          role: badRole,
        },
        deps,
      ),
    ).toThrow(InvalidRoleError);
  });

  it('toObject does not expose passwordHash and reflects public fields', () => {
    const user = User.create(
      {
        email: 'user@mail.com',
        name: 'User',
        passwordHash: 'secret-hash',
      },
      deps,
    );
    const obj = user.toObject();
    expect(obj).toStrictEqual({
      id: 'fixed-uuid',
      email: 'user@mail.com',
      name: 'User',
      role: Role.USER,
      createdAt: fixedDate,
      updatedAt: fixedDate,
    });
    // @ts-expect-error: passwordHash must not exist on the exposed object
    expect(obj.passwordHash).toBeUndefined();
    expect(JSON.stringify(user)).not.toContain('secret-hash');
  });

  it('rehydrate rebuilds the entity without altering data', () => {
    const hydrated = User.rehydrate({
      id: 'u-1',
      email: 'rehydrate@mail.com',
      name: 'Hydra',
      passwordHash: 'hash',
      role: Role.USER,
      createdAt: fixedDate,
      updatedAt: fixedDate,
    });
    expect(hydrated.id).toBe('u-1');
    expect(hydrated.email).toBe('rehydrate@mail.com');
    expect(hydrated.name).toBe('Hydra');
    expect(hydrated.role).toBe(Role.USER);
    expect(hydrated.createdAt).toEqual(fixedDate);
    expect(hydrated.updatedAt).toEqual(fixedDate);
    expect(hydrated.passwordHash).toBe('hash');
  });

  it('throws InvalidEmailError when email format is invalid', () => {
    const depsLocal = { uuid: () => 'id', now: () => fixedDate };
    expect(() =>
      User.create(
        { email: 'invalid-email', name: 'User', passwordHash: 'hash' },
        depsLocal,
      ),
    ).toThrow(InvalidEmailError);
  });

  it('rehydrate throws when persisted data is invalid (email)', () => {
    expect(() =>
      User.rehydrate({
        id: 'u-bad',
        email: 'not-an-email',
        name: 'User',
        passwordHash: 'hash',
        role: Role.USER,
        createdAt: fixedDate,
        updatedAt: fixedDate,
      }),
    ).toThrow(InvalidEmailError);
  });
});
