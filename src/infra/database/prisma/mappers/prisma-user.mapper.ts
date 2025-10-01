import { User as PrismaUser, Role as PrismaRole } from '@prisma/client';
import { User } from '@domain/users/entities/user.entity';
import { Role } from '@domain/users/enums/role.enum';

export const PrismaUserMapper = {
  toDomain(raw: PrismaUser): User {
    return User.rehydrate({
      id: raw.id,
      email: raw.email,
      name: raw.name,
      passwordHash: raw.password,
      role: raw.role as Role,
      createdAt: raw.createdAt,
      updatedAt: raw.updatedAt,
    });
  },

  toPrisma(user: User): PrismaUser {
    return {
      id: user.id,
      email: user.email,
      name: user.name,
      password: user.passwordHash,
      role: user.role as unknown as PrismaRole,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    } as unknown as PrismaUser;
  },
};
