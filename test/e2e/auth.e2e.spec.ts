import request from 'supertest';
import { INestApplication } from '@nestjs/common';
import type { Server } from 'http';
import { createTestingApp } from './helpers/app';
import { prisma, resetDatabase, disconnect } from './helpers/db';
import { seedAdmin } from './helpers/seed';
import { getCookieValue } from './helpers/cookie';

type AuthLoginResponse = {
  user: {
    email: string;
    role: 'ADMIN' | 'USER';
    name: string;
  };
};

describe('Auth E2E', () => {
  let app: INestApplication;
  let httpServer: Server;
  const cookieName = process.env.REFRESH_COOKIE_NAME ?? 'refreshToken';

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

  it('POST /auth/login → sets refresh cookie + returns Authorization header and user', async () => {
    const email = process.env.ADMIN_EMAIL ?? 'admin@example.com';
    const password = process.env.ADMIN_PASSWORD ?? 'changeme123';
    const resp = await request(httpServer)
      .post('/auth/login')
      .send({ email, password })
      .expect(200);
    expect(resp.headers['authorization']).toMatch(/^Bearer\s.+/);
    const refresh = getCookieValue(resp.headers['set-cookie'], cookieName);
    expect(refresh).toBeTruthy();
    const { user } = resp.body as AuthLoginResponse;
    expect(user.email).toBe(email.toLowerCase());
    expect(user.role).toBe('ADMIN');
    expect(typeof user.name).toBe('string');
    expect(user.name.length).toBeGreaterThan(0);
  });

  it('POST /auth/refresh → rotates cookie and returns new Authorization header', async () => {
    const email = process.env.ADMIN_EMAIL ?? 'admin@example.com';
    const password = process.env.ADMIN_PASSWORD ?? 'changeme123';

    const login = await request(httpServer)
      .post('/auth/login')
      .send({ email, password })
      .expect(200);
    const refreshValue = getCookieValue(
      login.headers['set-cookie'],
      cookieName,
    );
    expect(refreshValue).toBeTruthy();
    const resp = await request(httpServer)
      .post('/auth/refresh')
      .set('Cookie', `${cookieName}=${refreshValue as string}`)
      .expect(200);
    expect(resp.headers['authorization']).toMatch(/^Bearer\s.+/);
    const newRefresh = getCookieValue(resp.headers['set-cookie'], cookieName);
    expect(newRefresh).toBeTruthy();
  });

  it('POST /auth/logout → clears refresh cookie and revokes family', async () => {
    const email = process.env.ADMIN_EMAIL ?? 'admin@example.com';
    const password = process.env.ADMIN_PASSWORD ?? 'changeme123';
    const login = await request(httpServer)
      .post('/auth/login')
      .send({ email, password })
      .expect(200);
    const refreshValue = getCookieValue(
      login.headers['set-cookie'],
      cookieName,
    );
    expect(refreshValue).toBeTruthy();
    const resp = await request(httpServer)
      .post('/auth/logout')
      .set('Cookie', `${cookieName}=${refreshValue as string}`)
      .expect(200);
    const raw = resp.headers['set-cookie'];
    const cookies = raw ? (Array.isArray(raw) ? raw : [raw]) : [];
    const refreshCookies = cookies.filter((c: string) =>
      c.toLowerCase().startsWith(`${cookieName.toLowerCase()}=`),
    );

    if (refreshCookies.length > 0) {
      const cleared = refreshCookies.some((c: string) => {
        const lower = c.toLowerCase();
        return lower.includes('max-age=0') || lower.includes('expires=');
      });
      expect(cleared).toBe(true);
    }
    const tokens = await prisma.refreshToken.findMany();
    expect(tokens.length).toBeGreaterThan(0);
    expect(tokens.every((t) => t.revokedAt !== null)).toBe(true);
  });
});
