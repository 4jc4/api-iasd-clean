import 'dotenv/config';
import { PrismaClient } from '@prisma/client';
import * as argon2 from 'argon2';
const prisma = new PrismaClient();

function normalizeEmail(value: string): string {
  return value.trim().toLowerCase();
}

async function main() {
  const adminNameRaw = process.env.ADMIN_NAME ?? 'Admin';
  const adminEmailRaw = process.env.ADMIN_EMAIL ?? 'admin@example.com';
  const adminPassword = process.env.ADMIN_PASSWORD ?? 'changeme';
  const adminName = adminNameRaw.trim();
  const adminEmail = normalizeEmail(adminEmailRaw);
  if (!adminName) {
    throw new Error('ADMIN_NAME is empty after trimming');
  }
  if (!adminEmail) {
    throw new Error('ADMIN_EMAIL is empty after trimming');
  }
  if (process.env.NODE_ENV === 'production') {
    if (adminEmail === 'admin@example.com' || adminPassword === 'changeme') {
      throw new Error(
        'Refusing to seed admin with default credentials in production. Set ADMIN_EMAIL and ADMIN_PASSWORD.',
      );
    }
  }
  const hashed = await argon2.hash(adminPassword);
  await prisma.user.upsert({
    where: { email: adminEmail },
    update: {},
    create: {
      name: adminName,
      email: adminEmail,
      password: hashed,
      role: 'ADMIN',
    },
  });
  console.log(`✅ Admin ensured: ${adminEmail}`);
}

main()
  .catch((e) => {
    console.error('❌ Seed error:', e);
    process.exitCode = 1;
  })
  .finally(() => {
    void prisma.$disconnect();
  });
