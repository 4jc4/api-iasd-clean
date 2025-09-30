import { CreateUserUseCase } from '@/domain/users/use-cases/create-user.use-case';
import { Role } from '@/domain/users/enums/role.enum';
import {
  EmailAlreadyInUseError,
  UnauthorizedUserError,
} from '@/domain/users/errors/user.errors';
import { User } from '@/domain/users/entities/user.entity';
import { UserRepository } from '@/domain/users/repositories/user.repository';
import { HashGenerator } from '@/domain/shared/services/hash-generator';
import { UuidGenerator } from '@/domain/shared/services/uuid-generator';
import { Clock } from '@/domain/shared/services/clock';

describe('CreateUserUseCase', () => {
  const fixedDate = new Date('2024-01-01T00:00:00.000Z');
  const makeSut = () => {
    const repo: jest.Mocked<UserRepository> = {
      findById: jest.fn(),
      findByEmail: jest.fn(),
      save: jest.fn(),
    };
    const hash: jest.Mocked<HashGenerator> = {
      hash: jest.fn().mockResolvedValue('hashed-password'),
      compare: jest.fn(),
    };
    const uuid: jest.Mocked<UuidGenerator> = {
      generate: jest.fn().mockReturnValue('fixed-uuid'),
    };
    const clock: jest.Mocked<Clock> = {
      now: jest.fn().mockReturnValue(fixedDate),
    };
    const sut = new CreateUserUseCase(repo, hash, uuid, clock);
    return { sut, repo, hash, uuid, clock };
  };

  it('allows ADMIN to create user (happy path) and returns public object', async () => {
    const { sut, repo, hash, uuid, clock } = makeSut();
    repo.findByEmail.mockResolvedValue(null);
    const result = await sut.execute({
      requestingUserRole: Role.ADMIN,
      email: 'user@mail.com',
      name: 'Test User',
      password: '123',
    });
    expect(repo.findByEmail).toHaveBeenCalledWith('user@mail.com');
    expect(hash.hash).toHaveBeenCalledWith('123');
    expect(uuid.generate).toHaveBeenCalledTimes(1);
    expect(clock.now).toHaveBeenCalledTimes(1);
    expect(repo.save).toHaveBeenCalledWith(expect.any(User));
    expect(result.user).toStrictEqual({
      id: 'fixed-uuid',
      email: 'user@mail.com',
      name: 'Test User',
      role: Role.USER,
      createdAt: fixedDate,
      updatedAt: fixedDate,
    });
    expect('passwordHash' in result.user).toBe(false);
  });

  it('denies user creation for non-ADMIN requester', async () => {
    const { sut, repo, hash, uuid } = makeSut();
    await expect(
      sut.execute({
        requestingUserRole: Role.USER,
        email: 'user@mail.com',
        name: 'Test User',
        password: '123',
      }),
    ).rejects.toThrow(UnauthorizedUserError);
    expect(repo.findByEmail).not.toHaveBeenCalled();
    expect(hash.hash).not.toHaveBeenCalled();
    expect(uuid.generate).not.toHaveBeenCalled();
    expect(repo.save).not.toHaveBeenCalled();
  });

  it('denies creation when email already exists', async () => {
    const { sut, repo, hash } = makeSut();
    repo.findByEmail.mockResolvedValue(
      User.create(
        { email: 'user@mail.com', name: 'Dup', passwordHash: 'x' },
        { uuid: () => 'u', now: () => fixedDate },
      ),
    );
    await expect(
      sut.execute({
        requestingUserRole: Role.ADMIN,
        email: 'user@mail.com',
        name: 'Test User',
        password: '123',
      }),
    ).rejects.toThrow(EmailAlreadyInUseError);
    expect(hash.hash).not.toHaveBeenCalled();
    expect(repo.save).not.toHaveBeenCalled();
  });

  it('denies creation when email already exists (case/whitespace insensitive via repo contract)', async () => {
    const { sut, repo } = makeSut();
    repo.findByEmail.mockResolvedValue(
      User.create(
        { email: 'user@mail.com', name: 'Existing', passwordHash: 'hash' },
        { uuid: () => 'u', now: () => fixedDate },
      ),
    );
    await expect(
      sut.execute({
        requestingUserRole: Role.ADMIN,
        email: '   USER@MAIL.COM   ',
        name: 'Duplicate',
        password: '123',
      }),
    ).rejects.toThrow(EmailAlreadyInUseError);
    expect(repo.findByEmail).toHaveBeenCalledWith('user@mail.com');
  });

  it('entity still normalizes email/name and persists the created entity', async () => {
    const { sut, repo } = makeSut();
    repo.findByEmail.mockResolvedValue(null);
    const result = await sut.execute({
      requestingUserRole: Role.ADMIN,
      email: '  USER@MAIL.COM  ',
      name: '  Alice  ',
      password: 'abc',
    });
    expect(result.user).toStrictEqual({
      id: 'fixed-uuid',
      email: 'user@mail.com',
      name: 'Alice',
      role: Role.USER,
      createdAt: fixedDate,
      updatedAt: fixedDate,
    });
    expect(repo.save).toHaveBeenCalledWith(expect.any(User));
  });

  it('propagates error if hashing fails and does not save', async () => {
    const { sut, repo, hash } = makeSut();
    repo.findByEmail.mockResolvedValue(null);
    hash.hash.mockRejectedValue(new Error('hash failure'));
    await expect(
      sut.execute({
        requestingUserRole: Role.ADMIN,
        email: 'user@mail.com',
        name: 'User',
        password: 'secret',
      }),
    ).rejects.toThrow('hash failure');
    expect(repo.save).not.toHaveBeenCalled();
  });

  it('propagates error if persistence fails', async () => {
    const { sut, repo } = makeSut();
    repo.findByEmail.mockResolvedValue(null);
    repo.save.mockRejectedValue(new Error('db down'));
    await expect(
      sut.execute({
        requestingUserRole: Role.ADMIN,
        email: 'user@mail.com',
        name: 'User',
        password: '123',
      }),
    ).rejects.toThrow('db down');
  });

  it('allows ADMIN to specify the new user role (e.g., ADMIN)', async () => {
    const { sut, repo } = makeSut();
    repo.findByEmail.mockResolvedValue(null);
    const result = await sut.execute({
      requestingUserRole: Role.ADMIN,
      email: 'new-admin@mail.com',
      name: 'Root',
      password: 'root-pass',
      role: Role.ADMIN,
    });
    expect(result.user.role).toBe(Role.ADMIN);
  });

  it('propagates EmailAlreadyInUseError thrown by repository.save (unique violation race)', async () => {
    const fixedDate = new Date('2024-01-01T00:00:00.000Z');
    const repo: jest.Mocked<UserRepository> = {
      findById: jest.fn().mockResolvedValue(null),
      findByEmail: jest.fn().mockResolvedValue(null),
      save: jest
        .fn()
        .mockRejectedValue(new EmailAlreadyInUseError('user@mail.com')),
    };
    const hash: jest.Mocked<HashGenerator> = {
      hash: jest.fn().mockResolvedValue('hashed'),
      compare: jest.fn(),
    };
    const uuid: jest.Mocked<UuidGenerator> = {
      generate: jest.fn().mockReturnValue('id'),
    };
    const clock: jest.Mocked<Clock> = {
      now: jest.fn().mockReturnValue(fixedDate),
    };
    const sut = new CreateUserUseCase(repo, hash, uuid, clock);
    await expect(
      sut.execute({
        requestingUserRole: Role.ADMIN,
        email: 'user@mail.com',
        name: 'User',
        password: 'pwd',
      }),
    ).rejects.toThrow(EmailAlreadyInUseError);
    expect(repo.findByEmail).toHaveBeenCalled();
    expect(hash.hash).toHaveBeenCalled();
    expect(repo.save).toHaveBeenCalled();
  });
});
