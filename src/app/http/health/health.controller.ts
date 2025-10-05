import {
  Controller,
  Get,
  Head,
  HttpCode,
  HttpStatus,
  Res,
} from '@nestjs/common';
import type { Response } from 'express';

@Controller()
export class HealthController {
  @Get('healthz')
  @HttpCode(HttpStatus.OK)
  healthz(@Res({ passthrough: true }) res: Response) {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');
    return {
      ok: true,
      uptime: process.uptime(),
      timestamp: new Date().toISOString(),
    };
  }

  @Head('healthz')
  @HttpCode(HttpStatus.OK)
  healthzHead() {
    return;
  }
}
