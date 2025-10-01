import { z } from 'zod';

const isValidUrl = (value: string) => {
  try {
    const u = new URL(value);
    return Boolean(u.protocol && u.host);
  } catch {
    return false;
  }
};

const isPostgresUrl = (value: string) => {
  try {
    const u = new URL(value);
    return u.protocol === 'postgres:' || u.protocol === 'postgresql:';
  } catch {
    return false;
  }
};

export const envSchema = z
  .object({
    NODE_ENV: z
      .enum(['development', 'test', 'production'])
      .default('development'),
    PORT: z.coerce.number().int().positive().default(3000),
    CORS_ORIGIN: z.string().optional(),
    DATABASE_URL: z
      .string()
      .min(1, 'DATABASE_URL is required')
      .refine(isValidUrl, 'DATABASE_URL must be a valid URL')
      .refine(
        isPostgresUrl,
        'DATABASE_URL must use postgres:// or postgresql://',
      ),
    JWT_ACCESS_TOKEN_SECRET: z
      .string()
      .min(32, 'JWT_ACCESS_TOKEN_SECRET must be at least 32 characters'),
    ACCESS_TOKEN_TTL: z.string().default('15m'),
    ACCESS_TOKEN_ALG: z.enum(['HS256', 'HS384', 'HS512']).default('HS256'),
    REFRESH_TOKEN_TTL_MS: z.coerce
      .number()
      .int()
      .positive()
      .default(7 * 24 * 60 * 60 * 1000),
    REFRESH_SECRET_BYTES: z.coerce.number().int().positive().default(32),
    REFRESH_COOKIE_NAME: z.string().default('refreshToken'),
    REFRESH_COOKIE_SECURE: z.enum(['true', 'false']).default('false'),
    REFRESH_COOKIE_DOMAIN: z.string().optional(),
    REFRESH_COOKIE_SAMESITE: z.enum(['lax', 'strict', 'none']).default('lax'),
    ADMIN_NAME: z.string().optional(),
    ADMIN_EMAIL: z.email().optional(),
    ADMIN_PASSWORD: z.string().min(6).optional(),
    ARGON2_TYPE: z.enum(['id', 'i', 'd']).default('id').optional(),
    ARGON2_MEMORY_COST: z.coerce.number().int().positive().optional(),
    ARGON2_TIME_COST: z.coerce.number().int().positive().optional(),
    ARGON2_PARALLELISM: z.coerce.number().int().positive().optional(),
    ARGON2_HASH_LENGTH: z.coerce.number().int().positive().optional(),
  })
  .superRefine((env, ctx) => {
    if (
      env.REFRESH_COOKIE_SAMESITE === 'none' &&
      env.REFRESH_COOKIE_SECURE !== 'true'
    ) {
      ctx.addIssue({
        code: 'custom',
        path: ['REFRESH_COOKIE_SECURE'] as const,
        message:
          'When REFRESH_COOKIE_SAMESITE is "none", REFRESH_COOKIE_SECURE must be "true" (browser requirement).',
      });
    }
  });

export type Env = z.infer<typeof envSchema>;

export function validateEnv(config: Record<string, unknown>): Env {
  const parsed = envSchema.safeParse(config);
  if (!parsed.success) {
    const grouped: Record<string, string[]> = {};
    for (const issue of parsed.error.issues) {
      const path = issue.path.length ? issue.path.join('.') : '(root)';
      (grouped[path] ??= []).push(issue.message);
    }
    const lines = Object.entries(grouped).map(
      ([field, msgs]) => `${field}: ${msgs.join('; ')}`,
    );
    throw new Error(`Invalid environment variables:\n${lines.join('\n')}`);
  }
  return parsed.data;
}
