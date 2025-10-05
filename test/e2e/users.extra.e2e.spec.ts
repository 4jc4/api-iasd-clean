import request from 'supertest';
import { INestApplication } from '@nestjs/common';
import type { Server } from 'http';
import { createTestingApp } from './helpers/app';
import { prisma, resetDatabase, disconnect } from './helpers/db';
import * as argon2 from 'argon2';
import * as z from 'zod';

/** Zod schema to validate the create-user HTTP response shape */
const CreateUserResponseSchema = z.object({
  user: z.object({
    id: z.string(),
    email: z.string().email(),
    name: z.string(),
    role: z.enum(['ADMIN', 'USER']),
  }),
});
type CreateUserResponse = z.infer<typeof CreateUserResponseSchema>;

/** Simple login helper that returns the Authorization header (Bearer ...) */
async function login(httpServer: Server, email: string, password: string) {
  const res = await request(httpServer)
    .post('/auth/login')
    .send({ email, password });
  expect(res.status).toBe(200);
  const auth = res.headers['authorization'] as string | undefined;
  expect(auth).toMatch(/^Bearer\s.+/);
  return { auth: auth! };
}

describe('[E2E] Users extras (validation, duplicates, explicit role, RBAC)', () => {
  let app: INestApplication;
  let httpServer: Server;

  const ADMIN = {
    email: 'admin+e2e@mail.com',
    name: 'Admin E2E',
    password: 'Admin@123',
  };

  const USER = {
    email: 'user+e2e@mail.com',
    name: 'User E2E',
    password: 'User@123',
  };

  const BAD_ORIGIN = 'https://evil.example';

  beforeAll(async () => {
    app = await createTestingApp(); // global pipes/filters, CORS, exposed headers, etc.
    httpServer = app.getHttpServer() as unknown as Server;
  });

  afterAll(async () => {
    await resetDatabase();
    await app.close();
    await disconnect();
  });

  beforeEach(async () => {
    await resetDatabase();

    // Seed ADMIN and a normal USER
    await prisma.user.createMany({
      data: [
        {
          email: ADMIN.email,
          name: ADMIN.name,
          role: 'ADMIN',
          password: await argon2.hash(ADMIN.password),
        },
        {
          email: USER.email,
          name: USER.name,
          role: 'USER',
          password: await argon2.hash(USER.password),
        },
      ],
    });
  });

  describe('POST /users (create user)', () => {
    it('TC-U1 | 400 invalid payload (Zod): bad email / empty password', async () => {
      const { auth } = await login(httpServer, ADMIN.email, ADMIN.password);

      const res = await request(httpServer)
        .post('/users')
        .set('Authorization', auth)
        .send({
          email: 'not-an-email',
          name: '',
          password: '',
        });

      expect([400, 422]).toContain(res.status);
      expect(typeof res.body).toBe('object'); // error payload object
    });

    it('TC-U2 | 409 duplicate email is rejected', async () => {
      const { auth } = await login(httpServer, ADMIN.email, ADMIN.password);

      const payload = {
        email: 'dup@mail.com',
        name: 'Dup',
        password: 'Secret@123',
      };

      const first = await request(httpServer)
        .post('/users')
        .set('Authorization', auth)
        .send(payload);
      expect(first.status).toBe(201);

      const second = await request(httpServer)
        .post('/users')
        .set('Authorization', auth)
        .send(payload);

      // Prefer 409, but accept 400 depending on your error mapping
      expect([409, 400]).toContain(second.status);
    });

    it('TC-U3 | 403 USER cannot create another user (RBAC)', async () => {
      const { auth } = await login(httpServer, USER.email, USER.password);

      const res = await request(httpServer)
        .post('/users')
        .set('Authorization', auth)
        .send({
          email: 'nope@mail.com',
          name: 'Nope',
          password: 'Secret@123',
        });

      expect(res.status).toBe(403);
    });

    it('TC-U4 | 201 ADMIN can create with explicit role ADMIN (no password/passwordHash in body)', async () => {
      const { auth } = await login(httpServer, ADMIN.email, ADMIN.password);

      const res = await request(httpServer)
        .post('/users')
        .set('Authorization', auth)
        .send({
          email: 'boss@mail.com',
          name: 'Boss',
          password: 'Boss@123',
          role: 'ADMIN',
        });

      expect(res.status).toBe(201);

      const parsed: CreateUserResponse = CreateUserResponseSchema.parse(
        res.body,
      );
      const { user } = parsed;

      expect(user.role).toBe('ADMIN');
      // response sanitization
      expect(
        Object.prototype.hasOwnProperty.call(
          user as unknown as Record<string, unknown>,
          'password',
        ),
      ).toBe(false);
      expect(
        Object.prototype.hasOwnProperty.call(
          user as unknown as Record<string, unknown>,
          'passwordHash',
        ),
      ).toBe(false);
    });

    it('TC-U5 | 201 response is sanitized (no password/passwordHash fields)', async () => {
      const { auth } = await login(httpServer, ADMIN.email, ADMIN.password);

      const res = await request(httpServer)
        .post('/users')
        .set('Authorization', auth)
        .send({
          email: 'sanitized@mail.com',
          name: 'Sanitized',
          password: 'Secret@123',
        });

      expect(res.status).toBe(201);

      const parsed: CreateUserResponse = CreateUserResponseSchema.parse(
        res.body,
      );
      const { user } = parsed;

      expect(
        Object.prototype.hasOwnProperty.call(
          user as unknown as Record<string, unknown>,
          'password',
        ),
      ).toBe(false);
      expect(
        Object.prototype.hasOwnProperty.call(
          user as unknown as Record<string, unknown>,
          'passwordHash',
        ),
      ).toBe(false);
    });

    it('TC-U6 | 201 email is normalized to lowercase in persistence (case-insensitive input)', async () => {
      const { auth } = await login(httpServer, ADMIN.email, ADMIN.password);

      const mixed = 'Case.User+X@Mail.COM';
      const res = await request(httpServer)
        .post('/users')
        .set('Authorization', auth)
        .send({
          email: mixed,
          name: 'Case User',
          password: 'Secret@123',
        });

      expect(res.status).toBe(201);

      const created = await prisma.user.findUnique({
        where: { email: mixed.toLowerCase() },
      });
      expect(created).not.toBeNull();
      expect(created!.email).toBe(mixed.toLowerCase());
    });

    it("TC-U7 | 201 Bearer-only endpoint isn't CSRF-protected: invalid Origin/Referer don't block", async () => {
      const { auth } = await login(httpServer, ADMIN.email, ADMIN.password);

      const payload = {
        email: 'csrf@mail.com',
        name: 'CSRF Not Applied',
        password: 'Secret@123',
      };

      const res = await request(httpServer)
        .post('/users')
        .set('Authorization', auth)
        .set('Origin', BAD_ORIGIN)
        .set('Referer', `${BAD_ORIGIN}/attack`)
        .send(payload);

      // Because this endpoint uses Authorization header (not cookies), CSRF guard doesn't apply
      expect(res.status).toBe(201);

      // sanity: user is actually created
      const created = await prisma.user.findUnique({
        where: { email: payload.email },
      });
      expect(created).not.toBeNull();
    });

    it('TC-U8 | 403 USER cannot create ADMIN even if payload forges role', async () => {
      const { auth } = await login(httpServer, USER.email, USER.password);

      const res = await request(httpServer)
        .post('/users')
        .set('Authorization', auth)
        .send({
          email: 'cant-escalate@mail.com',
          name: 'Cant Escalate',
          password: 'Secret@123',
          role: 'ADMIN',
        });

      expect(res.status).toBe(403);

      // ensure nothing was created
      const created = await prisma.user.findUnique({
        where: { email: 'cant-escalate@mail.com' },
      });
      expect(created).toBeNull();
    });

    it('TC-U9 | password is stored hashed (argon2), not in plain text', async () => {
      const { auth } = await login(httpServer, ADMIN.email, ADMIN.password);

      const payload = {
        email: 'hashcheck@mail.com',
        name: 'Hash Check',
        password: 'Secret@123!',
      };

      const res = await request(httpServer)
        .post('/users')
        .set('Authorization', auth)
        .send(payload);
      expect(res.status).toBe(201);

      const created = await prisma.user.findUnique({
        where: { email: payload.email },
      });
      expect(created).not.toBeNull();

      // must exist and be different than plain password
      expect(created!.password).toBeDefined();
      expect(typeof created!.password).toBe('string');
      expect(created!.password).not.toBe(payload.password);

      // verify argon2 hash
      const ok = await argon2.verify(created!.password, payload.password);
      expect(ok).toBe(true);
    });

    it('TC-U10 | ADMIN creates a user who can then login (id looks like a UUID)', async () => {
      const { auth } = await login(httpServer, ADMIN.email, ADMIN.password);

      const payload = {
        email: 'login-after-create@mail.com',
        name: 'Login After Create',
        password: 'Secret@1234',
      };

      // create
      const createRes = await request(httpServer)
        .post('/users')
        .set('Authorization', auth)
        .send(payload);
      expect(createRes.status).toBe(201);

      const parsed: CreateUserResponse = CreateUserResponseSchema.parse(
        createRes.body,
      );
      const { user } = parsed;

      // UUID v4-like generic regex (covers common UUID forms)
      const uuidRegex =
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
      expect(user.id).toMatch(uuidRegex);
      expect(user.email).toBe(payload.email.toLowerCase());
      expect(user.name).toBe(payload.name);
      expect(user.role).toBe('USER'); // default role when omitted

      // can login
      const loginRes = await request(httpServer).post('/auth/login').send({
        email: payload.email,
        password: payload.password,
      });
      expect(loginRes.status).toBe(200);
      const authHeader = loginRes.headers['authorization'];
      expect(authHeader).toMatch(/^Bearer\s.+/);
    });

    it('TC-U11 | 401 when Authorization header is missing', async () => {
      const res = await request(httpServer).post('/users').send({
        email: 'no-auth@mail.com',
        name: 'No Auth',
        password: 'Secret@123',
      });

      expect(res.status).toBe(401);
    });

    it('TC-U12 | 400/201 payload ignores unexpected fields (DTO whitelist)', async () => {
      const { auth } = await login(httpServer, ADMIN.email, ADMIN.password);

      // Try to smuggle `id` and `passwordHash` in payload — they must be ignored and not persisted
      const payloadWithExtra = {
        email: 'whitelist@mail.com',
        name: 'DTO Whitelist',
        password: 'Secret@123',
        id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
        passwordHash: 'fake-hash',
        role: 'USER',
      } as unknown as Record<string, unknown>;

      const res = await request(httpServer)
        .post('/users')
        .set('Authorization', auth)
        .send(payloadWithExtra);

      // Depending on your validation, this can be 201 (ignored extras) or 400 (strict schema).
      // We assert both possibilities and then verify persistence is correct.
      expect([201, 400]).toContain(res.status);

      // If created, ensure db ignored extra fields
      if (res.status === 201) {
        const created = await prisma.user.findUnique({
          where: { email: 'whitelist@mail.com' },
        });
        expect(created).not.toBeNull();
        // id should be generated by DB, not the forged one
        expect(created!.id).not.toBe('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa');
        // no leaked passwordHash
        expect(created!.password).toBeDefined();
        expect(created!.password).not.toBe('fake-hash');
      }
    });
  });
});
