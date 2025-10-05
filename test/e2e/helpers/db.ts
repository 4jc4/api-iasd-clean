import { PrismaClient } from '@prisma/client';

export const prisma = new PrismaClient();

export async function resetDatabase() {
  await prisma.refreshToken.deleteMany({});
  await prisma.user.deleteMany({});
}

export async function disconnect() {
  await prisma.$disconnect();
}
