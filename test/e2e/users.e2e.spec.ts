import request from 'supertest';
import { INestApplication } from '@nestjs/common';
import type { Server } from 'http';
import { createTestingApp } from './helpers/app';
import { resetDatabase, disconnect, prisma } from './helpers/db';
import { seedAdmin } from './helpers/seed';
import { hash as argon2Hash } from 'argon2';

type CreateUserResponse = {
  user: {
    email: string;
    name: string;
    role: 'ADMIN' | 'USER';
  };
};

async function loginAsAdmin(server: Server): Promise<{ authz: string }> {
  const email = process.env.ADMIN_EMAIL ?? 'admin@example.com';
  const password = process.env.ADMIN_PASSWORD ?? 'changeme123';
  const resp = await request(server)
    .post('/auth/login')
    .send({ email, password })
    .expect(200);
  const authz = resp.headers['authorization'];
  return { authz };
}

async function createUserAndLogin(
  server: Server,
  opts?: { email?: string; name?: string; password?: string },
): Promise<{ authz: string; email: string; name: string }> {
  const email = opts?.email ?? 'user1@mail.com';
  const name = opts?.name ?? 'Regular User';
  const password = opts?.password ?? 'userpass123';
  const passwordHash = await argon2Hash(password);
  await prisma.user.create({
    data: {
      email,
      name,
      password: passwordHash,
      role: 'USER',
    },
  });
  const login = await request(server)
    .post('/auth/login')
    .send({ email, password })
    .expect(200);
  const authz = login.headers['authorization'];
  return { authz, email, name };
}

describe('Users E2E', () => {
  let app: INestApplication;
  let httpServer: Server;

  beforeAll(async () => {
    app = await createTestingApp();
    httpServer = app.getHttpServer() as unknown as Server;
  });

  afterAll(async () => {
    await resetDatabase();
    await app.close();
    await disconnect();
  });

  beforeEach(async () => {
    await resetDatabase();
    await seedAdmin();
  });

  it('POST /users → 201 when ADMIN creates a new user', async () => {
    const { authz } = await loginAsAdmin(httpServer);
    const resp = await request(httpServer)
      .post('/users')
      .set('Authorization', authz)
      .send({
        email: 'newuser@mail.com',
        name: 'New User',
        password: 'secret123',
        role: 'USER',
      })
      .expect(201);
    const { user } = resp.body as CreateUserResponse;
    expect(user).toMatchObject({
      email: 'newuser@mail.com',
      name: 'New User',
      role: 'USER',
    });
    const found = await prisma.user.findUnique({
      where: { email: 'newuser@mail.com' },
    });
    expect(found).not.toBeNull();
  });

  it('POST /users → 401 when token is invalid (JwtAuthGuard)', async () => {
    await request(httpServer)
      .post('/users')
      .set('Authorization', 'Bearer invalid.token.here')
      .send({
        email: 'x@mail.com',
        name: 'X',
        password: 'abc12345',
        role: 'USER',
      })
      .expect(401);
  });

  it('POST /users → 409 when email already exists', async () => {
    const { authz } = await loginAsAdmin(httpServer);
    await request(httpServer)
      .post('/users')
      .set('Authorization', authz)
      .send({
        email: 'dup@mail.com',
        name: 'Dup',
        password: 'abc12345',
        role: 'USER',
      })
      .expect(201);
    await request(httpServer)
      .post('/users')
      .set('Authorization', authz)
      .send({
        email: 'dup@mail.com',
        name: 'Dup 2',
        password: 'abc12345',
        role: 'USER',
      })
      .expect(409);
  });

  it('POST /users → 403 when USER tries to create a user (RolesGuard)', async () => {
    const { authz } = await createUserAndLogin(httpServer, {
      email: 'regular@mail.com',
      name: 'Regular',
      password: 'userpass123',
    });
    await request(httpServer)
      .post('/users')
      .set('Authorization', authz)
      .send({
        email: 'someone@mail.com',
        name: 'Someone',
        password: 'strongpass',
        role: 'USER',
      })
      .expect(403);
  });
});
