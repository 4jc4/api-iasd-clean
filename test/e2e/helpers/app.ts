import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { AppModule } from '@/app.module';
import { ConfigService } from '@nestjs/config';
import cookieParser from 'cookie-parser';
import { DomainExceptionFilter } from '@/app/http/filters/domain-exception.filter';

function parseCorsOrigins(origins?: string): boolean | string[] {
  if (!origins || origins.trim() === '') return true;
  return origins
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

export async function createTestingApp(): Promise<INestApplication> {
  const moduleRef = await Test.createTestingModule({
    imports: [AppModule],
  }).compile();
  const app = moduleRef.createNestApplication();
  app.use(cookieParser());
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
  await app.init();
  return app;
}
