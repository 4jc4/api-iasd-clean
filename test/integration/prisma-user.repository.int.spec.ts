import { PrismaUserRepository } from '@/infra/database/prisma/repositories/prisma-user.repository';
import { PrismaService } from '@/infra/database/prisma/prisma.service';
import { resetDatabase, disconnect } from './helpers/db';
import { User } from '@/domain/users/entities/user.entity';
import { Role } from '@/domain/users/enums/role.enum';
import { EmailAlreadyInUseError } from '@/domain/users/errors/user.errors';

describe('PrismaUserRepository (integration)', () => {
  const prisma = new PrismaService();
  const repo = new PrismaUserRepository(prisma);
  const fixedDate = new Date('2024-01-01T00:00:00.000Z');

  beforeAll(async () => {
    await prisma.$connect();
  });

  afterAll(async () => {
    await resetDatabase();
    await disconnect();
  });

  beforeEach(async () => {
    await resetDatabase();
  });

  function makeUser(
    params?: Partial<{ email: string; name: string; role: Role }>,
  ) {
    return User.rehydrate({
      id: 'u-1',
      email: params?.email ?? 'user@mail.com',
      name: params?.name ?? 'User',
      passwordHash: 'hashed',
      role: params?.role ?? Role.USER,
      createdAt: fixedDate,
      updatedAt: fixedDate,
    });
  }

  it('saves a new user and finds by id', async () => {
    const u = makeUser();
    await repo.save(u);
    const found = await repo.findById(u.id);
    expect(found).not.toBeNull();
    expect(found?.email).toBe('user@mail.com');
    expect(found?.name).toBe('User');
    expect(found?.role).toBe(Role.USER);
  });

  it('findByEmail respects normalization and returns the user', async () => {
    const u = makeUser({ email: 'user@mail.com' });
    await repo.save(u);
    const found = await repo.findByEmail('  USER@mail.com  ');
    expect(found?.id).toBe('u-1');
  });

  it('maps unique email violation to EmailAlreadyInUseError', async () => {
    const a = makeUser({ email: 'user@mail.com', name: 'A' });
    const b = User.rehydrate({
      id: 'u-2',
      email: 'user@mail.com',
      name: 'B',
      passwordHash: 'hashed',
      role: Role.USER,
      createdAt: fixedDate,
      updatedAt: fixedDate,
    });
    await repo.save(a);
    await expect(repo.save(b)).rejects.toBeInstanceOf(EmailAlreadyInUseError);
  });

  it('upsert behavior: save called twice updates existing record', async () => {
    const u = makeUser();
    await repo.save(u);
    const updated = User.rehydrate({
      ...u.toObject(),
      id: u.id,
      email: 'user@mail.com',
      name: 'User Updated',
      role: Role.ADMIN,
      passwordHash: 'new-hash',
      createdAt: u.createdAt,
      updatedAt: new Date('2024-01-02T00:00:00.000Z'),
    });
    await repo.save(updated);
    const found = await repo.findById(u.id);
    expect(found?.name).toBe('User Updated');
    expect(found?.role).toBe(Role.ADMIN);
  });
});
