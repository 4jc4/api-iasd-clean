import { Injectable } from '@nestjs/common';
import { PrismaService } from '@infra/database/prisma/prisma.service';
import { UserRepository } from '@domain/users/repositories/user.repository';
import { User } from '@domain/users/entities/user.entity';
import { EmailAlreadyInUseError } from '@domain/users/errors/user.errors';
import { Prisma } from '@prisma/client';
import { PrismaUserMapper } from '../mappers/prisma-user.mapper';
import { normalizeEmail } from '@domain/shared/utils/email';

function isString(x: unknown): x is string {
  return typeof x === 'string';
}

function hasTarget(o: unknown): o is { target?: unknown } {
  return !!o && typeof o === 'object' && 'target' in o;
}

function getUniqueViolationTarget(
  err: Prisma.PrismaClientKnownRequestError,
): string[] | string | undefined {
  const meta = err.meta;
  if (!hasTarget(meta)) return undefined;
  const t = meta.target;
  if (Array.isArray(t) && t.every(isString)) return t;
  if (isString(t)) return t;
  return undefined;
}

@Injectable()
export class PrismaUserRepository implements UserRepository {
  constructor(private readonly prisma: PrismaService) {}

  async findById(id: string): Promise<User | null> {
    const raw = await this.prisma.user.findUnique({ where: { id } });
    return raw ? PrismaUserMapper.toDomain(raw) : null;
  }

  async findByEmail(emailRaw: string): Promise<User | null> {
    const email = normalizeEmail(emailRaw);
    const raw = await this.prisma.user.findFirst({
      where: { email: { equals: email } },
    });
    return raw ? PrismaUserMapper.toDomain(raw) : null;
  }

  async save(user: User): Promise<void> {
    try {
      await this.prisma.user.upsert({
        where: { id: user.id },
        create: {
          id: user.id,
          email: user.email,
          name: user.name,
          password: user.passwordHash,
          role: user.role,
          createdAt: user.createdAt,
          updatedAt: user.updatedAt,
        },
        update: {
          email: user.email,
          name: user.name,
          password: user.passwordHash,
          role: user.role,
          updatedAt: user.updatedAt,
        },
      });
    } catch (e) {
      if (
        e instanceof Prisma.PrismaClientKnownRequestError &&
        e.code === 'P2002'
      ) {
        const target = getUniqueViolationTarget(e);
        const isEmailUniqueViolation = Array.isArray(target)
          ? target.includes('email')
          : target === 'email';

        if (isEmailUniqueViolation) {
          throw new EmailAlreadyInUseError(user.email);
        }
      }
      throw e;
    }
  }
}
