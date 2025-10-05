import request from 'supertest';
import { INestApplication } from '@nestjs/common';
import type { Server } from 'http';
import { createTestingApp } from './helpers/app';
import { prisma, resetDatabase, disconnect } from './helpers/db';
import * as argon2 from 'argon2';

/** Read raw Set-Cookie header lines as-is */
function getRawSetCookie(res: request.Response): string[] {
  const raw = res.headers['set-cookie'];
  return Array.isArray(raw) ? raw : raw ? [raw] : [];
}

/** Extract a cookie value by name from Set-Cookie lines */
function findCookieValue(
  setCookies: string[],
  name: string,
): string | undefined {
  for (const line of setCookies) {
    const m = line.match(new RegExp(`^${name}=([^;]+)`));
    if (m) return m[1];
  }
  return undefined;
}

describe('[E2E] Auth extras (negatives & edges)', () => {
  let app: INestApplication;
  let httpServer: Server;

  const cookieName = process.env.REFRESH_COOKIE_NAME ?? 'refreshToken';

  const ADMIN = {
    email: 'admin+e2e@mail.com',
    name: 'Admin E2E',
    password: 'Admin@123',
  };

  const GOOD_ORIGIN = 'http://localhost:3000';
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

    // Seed ADMIN (schema uses "password" field hashed with argon2)
    await prisma.user.upsert({
      where: { email: ADMIN.email },
      create: {
        email: ADMIN.email,
        name: ADMIN.name,
        role: 'ADMIN',
        password: await argon2.hash(ADMIN.password),
      },
      update: {},
    });
  });

  describe('POST /auth/login (negative and headers)', () => {
    it('TC-A1 | 401 invalid credentials (no Authorization and no Set-Cookie)', async () => {
      const res = await request(httpServer).post('/auth/login').send({
        email: ADMIN.email,
        password: 'wrong_password',
      });

      expect(res.status).toBe(401);
      expect(res.headers['authorization']).toBeUndefined();
      expect(getRawSetCookie(res).length).toBe(0);
    });

    it('TC-A2 | 400 invalid payload (Zod) — missing/invalid email', async () => {
      const res = await request(httpServer).post('/auth/login').send({
        email: 'not-an-email',
        password: '',
      });

      expect([400, 422]).toContain(res.status);
      expect(res.headers['authorization']).toBeUndefined();
      expect(getRawSetCookie(res).length).toBe(0);
      expect(typeof res.body).toBe('object');
    });

    it('TC-A3 | 200 correct cache headers and Vary', async () => {
      const res = await request(httpServer).post('/auth/login').send({
        email: ADMIN.email,
        password: ADMIN.password,
      });

      // In your project, login returns 200
      expect(res.status).toBe(200);
      const auth = res.headers['authorization'];
      expect(auth).toMatch(/^Bearer\s.+/);

      const cookies = getRawSetCookie(res);
      expect(cookies.length).toBeGreaterThan(0);
      const cookie = cookies.join(';');
      expect(cookie).toMatch(/HttpOnly/i);
      expect(cookie).toMatch(/Path=\//i);

      // Cache/Vary
      expect(res.headers['cache-control']).toMatch(/no-store/i);
      expect(res.headers['pragma'] ?? '').toMatch(/no-cache/i);
      const vary = res.headers['vary'] ?? '';
      expect(vary).toMatch(/Origin/i);
      expect(vary).toMatch(/Cookie/i);
    });

    it('TC-A4 | CORS: Access-Control-Expose-Headers includes Authorization on /auth/login', async () => {
      const res = await request(httpServer).post('/auth/login').send({
        email: ADMIN.email,
        password: ADMIN.password,
      });

      expect(res.status).toBe(200);

      const expose = res.headers['access-control-expose-headers'] ?? '';
      expect(expose).toMatch(/authorization/i);

      const auth = res.headers['authorization'];
      expect(auth).toMatch(/^Bearer\s.+/);
    });
  });

  describe('POST /auth/refresh (missing, malformed, CSRF, reuse, RTR)', () => {
    it('TC-R1 | 401 missing refresh cookie', async () => {
      const res = await request(httpServer).post('/auth/refresh');
      expect([401, 403]).toContain(res.status);
      expect(res.headers['authorization']).toBeUndefined();
      expect(getRawSetCookie(res).length).toBe(0);
    });

    it('TC-R2 | 401 malformed cookie (Cookie header must be a string)', async () => {
      const res = await request(httpServer)
        .post('/auth/refresh')
        .set('Cookie', `${cookieName}=invalid-refresh-value`);
      expect([401, 403]).toContain(res.status);
      expect(res.headers['authorization']).toBeUndefined();
    });

    it('TC-R3 | 403 CSRF (invalid Origin/Referer)', async () => {
      // login to obtain a valid refresh
      const login = await request(httpServer)
        .post('/auth/login')
        .send({ email: ADMIN.email, password: ADMIN.password });
      expect(login.status).toBe(200);
      const cookies = getRawSetCookie(login);
      expect(cookies.length).toBeGreaterThan(0);

      // attempt refresh with malicious Origin/Referer
      const res = await request(httpServer)
        .post('/auth/refresh')
        .set('Cookie', cookies)
        .set('Origin', BAD_ORIGIN)
        .set('Referer', `${BAD_ORIGIN}/page`);

      expect(res.status).toBe(403);
      expect(res.headers['authorization']).toBeUndefined();
    });

    it('TC-R4 | reuse detection: reusing A fails, but current token B remains valid', async () => {
      // 1) login -> cookie A
      const login = await request(httpServer)
        .post('/auth/login')
        .send({ email: ADMIN.email, password: ADMIN.password });
      expect(login.status).toBe(200);
      const cookieA = getRawSetCookie(login);

      // 2) refresh with A -> cookie B
      const refresh1 = await request(httpServer)
        .post('/auth/refresh')
        .set('Cookie', cookieA);
      expect(refresh1.status).toBe(200);
      expect(refresh1.headers['authorization']).toMatch(/^Bearer\s.+/);
      const cookieB = getRawSetCookie(refresh1);
      expect(cookieB.length).toBeGreaterThan(0);

      // 3) reuse A => should fail
      const reuse = await request(httpServer)
        .post('/auth/refresh')
        .set('Cookie', cookieA);
      expect([401, 403]).toContain(reuse.status);

      // 4) current policy: family NOT revoked; B still valid
      const refreshWithB = await request(httpServer)
        .post('/auth/refresh')
        .set('Cookie', cookieB);
      expect(refreshWithB.status).toBe(200);
      expect(refreshWithB.headers['authorization']).toMatch(/^Bearer\s.+/);
      const cookieC = getRawSetCookie(refreshWithB);
      expect(cookieC.length).toBeGreaterThan(0);
    });

    it('TC-R5 | 200 cookie attributes and new Authorization are set', async () => {
      const login = await request(httpServer)
        .post('/auth/login')
        .send({ email: ADMIN.email, password: ADMIN.password });
      const cookieA = getRawSetCookie(login);

      const res = await request(httpServer)
        .post('/auth/refresh')
        .set('Cookie', cookieA);
      expect(res.status).toBe(200);
      expect(res.headers['authorization']).toMatch(/^Bearer\s.+/);

      const cookies = getRawSetCookie(res);
      expect(cookies.length).toBeGreaterThan(0);
      const c = cookies.join(';');
      expect(c).toMatch(/HttpOnly/i);
      expect(c).toMatch(/Path=\//i);
      if (/SameSite=None/i.test(c)) {
        expect(c).toMatch(/Secure/i);
      }
    });

    it('TC-R6 | 401/403 when refresh token is expired (TTL)', async () => {
      // login to obtain refresh
      const login = await request(httpServer)
        .post('/auth/login')
        .send({ email: ADMIN.email, password: ADMIN.password });
      expect(login.status).toBe(200);
      const cookieA = getRawSetCookie(login);
      expect(cookieA.length).toBeGreaterThan(0);

      // find latest refresh for ADMIN and force expiration
      const admin = await prisma.user.findUnique({
        where: { email: ADMIN.email },
      });
      expect(admin).not.toBeNull();

      const latest = await prisma.refreshToken.findFirst({
        where: { userId: admin!.id },
        orderBy: { createdAt: 'desc' },
      });
      expect(latest).not.toBeNull();

      await prisma.refreshToken.update({
        where: { id: latest!.id },
        data: { expiresAt: new Date(Date.now() - 1_000) },
      });

      // attempt /auth/refresh with expired cookie
      const res = await request(httpServer)
        .post('/auth/refresh')
        .set('Cookie', cookieA)
        .set('Origin', GOOD_ORIGIN)
        .set('Referer', `${GOOD_ORIGIN}/page`);

      expect([401, 403]).toContain(res.status);
      expect(res.headers['authorization']).toBeUndefined();
    });

    it('TC-R7 | CORS: Access-Control-Expose-Headers includes Authorization on /auth/refresh', async () => {
      // login to obtain refresh cookie
      const login = await request(httpServer).post('/auth/login').send({
        email: ADMIN.email,
        password: ADMIN.password,
      });
      expect(login.status).toBe(200);
      const cookies = getRawSetCookie(login);
      expect(cookies.length).toBeGreaterThan(0);

      // refresh (omit Origin/Referer to avoid CSRF guard)
      const res = await request(httpServer)
        .post('/auth/refresh')
        .set('Cookie', cookies);
      expect(res.status).toBe(200);

      const expose = res.headers['access-control-expose-headers'] ?? '';
      expect(expose).toMatch(/authorization/i);

      const auth = res.headers['authorization'];
      expect(auth).toMatch(/^Bearer\s.+/);
    });

    it('TC-R8 | RTR: each /auth/refresh rotates the refresh cookie; old value reuse fails', async () => {
      // 1) login -> cookie A
      const login = await request(httpServer)
        .post('/auth/login')
        .send({ email: ADMIN.email, password: ADMIN.password });
      expect(login.status).toBe(200);
      const cookieAAll = getRawSetCookie(login);
      const refreshA = findCookieValue(cookieAAll, cookieName);
      expect(refreshA).toBeDefined();

      // 2) refresh with A -> cookie B (must differ from A)
      const refresh1 = await request(httpServer)
        .post('/auth/refresh')
        .set('Cookie', cookieAAll);
      expect(refresh1.status).toBe(200);
      const cookieBAll = getRawSetCookie(refresh1);
      const refreshB = findCookieValue(cookieBAll, cookieName);
      expect(refreshB).toBeDefined();
      expect(refreshB).not.toBe(refreshA);

      // 3) reuse A again => must fail (reuse detected)
      const reuse = await request(httpServer)
        .post('/auth/refresh')
        .set('Cookie', cookieAAll);
      expect([401, 403]).toContain(reuse.status);
    });

    it('TC-R9 | RTR also rotates the access token (Authorization changes between consecutive refreshes)', async () => {
      // 1) login -> cookie A
      const login = await request(httpServer)
        .post('/auth/login')
        .send({ email: ADMIN.email, password: ADMIN.password });
      expect(login.status).toBe(200);
      const cookieA = getRawSetCookie(login);
      expect(cookieA.length).toBeGreaterThan(0);

      // 2) refresh with A -> token #1 and cookie B
      const refresh1 = await request(httpServer)
        .post('/auth/refresh')
        .set('Cookie', cookieA);
      expect(refresh1.status).toBe(200);
      const auth1 = refresh1.headers['authorization'];
      expect(auth1).toMatch(/^Bearer\s.+/);
      const cookieB = getRawSetCookie(refresh1);
      expect(cookieB.length).toBeGreaterThan(0);

      // small delay to ensure different iat/jti
      await new Promise((r) => setTimeout(r, 1100));

      // 3) refresh with B -> token #2 (must differ from #1)
      const refresh2 = await request(httpServer)
        .post('/auth/refresh')
        .set('Cookie', cookieB);
      expect(refresh2.status).toBe(200);
      const auth2 = refresh2.headers['authorization'];
      expect(auth2).toMatch(/^Bearer\s.+/);

      expect(auth2).not.toBe(auth1);
    });

    it('TC-R10 | concurrent refresh with the same cookie: allow 1..2 successes, but reusing A afterwards fails (RTR)', async () => {
      // 1) login → cookie A
      const loginRes = await request(httpServer)
        .post('/auth/login')
        .send({ email: ADMIN.email, password: ADMIN.password });
      expect(loginRes.status).toBe(200);
      const cookieAAll = getRawSetCookie(loginRes);
      expect(cookieAAll.length).toBeGreaterThan(0);

      // 2) fire two refresh calls in parallel with the same cookie A
      const [r1, r2] = await Promise.all([
        request(httpServer).post('/auth/refresh').set('Cookie', cookieAAll),
        request(httpServer).post('/auth/refresh').set('Cookie', cookieAAll),
      ]);

      // accept 1 or 2 successes (200), but not 0
      const statuses = [r1.status, r2.status];
      const successCount = statuses.filter((s) => s === 200).length;
      expect(successCount).toBeGreaterThanOrEqual(1);

      // at least one returned cookie value must differ from A (rotation happened)
      const r1Cookies = getRawSetCookie(r1);
      const r2Cookies = getRawSetCookie(r2);
      const rotatedValues = [r1Cookies, r2Cookies]
        .map((c) => findCookieValue(c, cookieName))
        .filter((v): v is string => typeof v === 'string');

      expect(rotatedValues.length).toBeGreaterThanOrEqual(1);
      const valA = findCookieValue(cookieAAll, cookieName);
      expect(valA).toBeDefined();
      expect(rotatedValues.some((v) => v !== valA)).toBe(true);

      // 3) reusing A AFTER the race must fail (A is invalid)
      const reuseAfter = await request(httpServer)
        .post('/auth/refresh')
        .set('Cookie', cookieAAll);
      expect([401, 403]).toContain(reuseAfter.status);
    });

    it('TC-R11 | RTR chain: after B→C, reusing B fails (401/403)', async () => {
      // 1) login -> cookie A
      const login = await request(httpServer)
        .post('/auth/login')
        .send({ email: ADMIN.email, password: ADMIN.password });
      expect(login.status).toBe(200);
      const cookieAAll = getRawSetCookie(login);

      // 2) refresh with A -> cookie B
      const r1 = await request(httpServer)
        .post('/auth/refresh')
        .set('Cookie', cookieAAll);
      expect(r1.status).toBe(200);
      const cookieBAll = getRawSetCookie(r1);
      const valB = findCookieValue(cookieBAll, cookieName);
      expect(valB).toBeDefined();

      // 3) refresh with B -> cookie C (must differ from B)
      const r2 = await request(httpServer)
        .post('/auth/refresh')
        .set('Cookie', cookieBAll);
      expect(r2.status).toBe(200);
      const cookieCAll = getRawSetCookie(r2);
      const valC = findCookieValue(cookieCAll, cookieName);
      expect(valC).toBeDefined();
      expect(valC).not.toBe(valB);

      // 4) reuse B again => must fail (reuse)
      const reuseB = await request(httpServer)
        .post('/auth/refresh')
        .set('Cookie', cookieBAll);
      expect([401, 403]).toContain(reuseB.status);
    });
  });

  describe('POST /auth/logout (idempotency and CSRF)', () => {
    it('TC-L1 | 200/204 idempotent without cookie', async () => {
      const res = await request(httpServer).post('/auth/logout');
      expect([200, 204]).toContain(res.status);
    });

    it('TC-L2 | 200 clears cookie and blocks subsequent refresh', async () => {
      const login = await request(httpServer)
        .post('/auth/login')
        .send({ email: ADMIN.email, password: ADMIN.password });
      const cookieA = getRawSetCookie(login);

      const out = await request(httpServer)
        .post('/auth/logout')
        .set('Cookie', cookieA);
      expect([200, 204]).toContain(out.status);

      const cleared = getRawSetCookie(out).join(';');
      expect(cleared).toMatch(/Max-Age=0|Expires=/i);

      const after = await request(httpServer)
        .post('/auth/refresh')
        .set('Cookie', cookieA);
      expect([401, 403]).toContain(after.status);
    });

    it('TC-L3 | 403 CSRF (logout with invalid Origin/Referer)', async () => {
      const login = await request(httpServer)
        .post('/auth/login')
        .send({ email: ADMIN.email, password: ADMIN.password });
      const cookieA = getRawSetCookie(login);

      const res = await request(httpServer)
        .post('/auth/logout')
        .set('Cookie', cookieA)
        .set('Origin', BAD_ORIGIN)
        .set('Referer', `${BAD_ORIGIN}/page`);

      expect([403]).toContain(res.status);
      // should NOT clear cookie when blocked by CSRF
      const cookies = getRawSetCookie(res);
      if (cookies.length > 0) {
        const c = cookies.join(';');
        expect(c).not.toMatch(/Max-Age=0|Expires=/i);
      }
    });
  });
});
