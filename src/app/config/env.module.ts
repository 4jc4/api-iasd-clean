import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { validateEnv } from '@/app/config/env.schema';

const envFilePath = [`.env.${process.env.NODE_ENV ?? 'development'}`, '.env'];

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      cache: true,
      expandVariables: true,
      envFilePath,
      validate: validateEnv,
    }),
  ],
})
export class EnvModule {}
