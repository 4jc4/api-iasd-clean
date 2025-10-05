import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ConfigService } from '@nestjs/config';
import cookieParser from 'cookie-parser';
import helmet, { type HelmetOptions } from 'helmet';
import type { RequestHandler } from 'express';
import { DomainExceptionFilter } from '@/app/http/filters/domain-exception.filter';

function parseCorsOrigins(origins?: string): boolean | string[] {
  if (!origins || origins.trim() === '') return true; // dev: libera tudo
  return origins
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.use((cookieParser as unknown as () => RequestHandler)());
  app.use(
    (helmet as unknown as (opts?: Readonly<HelmetOptions>) => RequestHandler)(
      {},
    ),
  );
  (
    app.getHttpAdapter().getInstance() as unknown as import('express').Express
  ).set('trust proxy', 1);
  const cfg = app.get(ConfigService);
  const origins = parseCorsOrigins(cfg.get<string>('CORS_ORIGIN'));
  app.enableCors({
    origin: origins,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    exposedHeaders: ['Authorization'],
  });
  app.useGlobalFilters(new DomainExceptionFilter());
  app.enableShutdownHooks();
  const port = Number(cfg.get('PORT')) || 3000;
  await app.listen(port);
}

void bootstrap();
