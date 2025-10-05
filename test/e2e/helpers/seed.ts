import { prisma } from './db';
import * as argon2 from 'argon2';

export async function seedAdmin() {
  const name = process.env.ADMIN_NAME ?? 'Admin';
  const email = (process.env.ADMIN_EMAIL ?? 'admin@example.com')
    .trim()
    .toLowerCase();
  const password = process.env.ADMIN_PASSWORD ?? 'changeme123';
  const hash = await argon2.hash(password);
  await prisma.user.upsert({
    where: { email },
    update: { name, password: hash, role: 'ADMIN' },
    create: { name, email, password: hash, role: 'ADMIN' },
  });
  return { email, password };
}
