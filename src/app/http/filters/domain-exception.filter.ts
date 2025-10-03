import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { Request, Response } from 'express';

const DOMAIN_ERROR_STATUS: Record<string, number> = {
  InvalidCredentialsError: HttpStatus.UNAUTHORIZED,
  RefreshTokenNotFoundError: HttpStatus.UNAUTHORIZED,
  RefreshTokenExpiredError: HttpStatus.UNAUTHORIZED,
  RefreshTokenRevokedError: HttpStatus.UNAUTHORIZED,
  RefreshTokenReuseDetectedError: HttpStatus.UNAUTHORIZED,
  UnauthorizedUserError: HttpStatus.FORBIDDEN,
  EmailAlreadyInUseError: HttpStatus.CONFLICT,
  InvalidEmailError: HttpStatus.UNPROCESSABLE_ENTITY,
  InvalidNameError: HttpStatus.UNPROCESSABLE_ENTITY,
  InvalidRoleError: HttpStatus.UNPROCESSABLE_ENTITY,
  InvariantViolationError: HttpStatus.UNPROCESSABLE_ENTITY,
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function hasStringProp<K extends string>(
  value: unknown,
  key: K,
): value is Record<K, string> {
  if (!isRecord(value)) return false;
  const rec = value;
  const v = rec[key];
  return typeof v === 'string';
}

function getErrName(e: unknown): string {
  if (e instanceof Error && typeof e.name === 'string') return e.name;
  if (hasStringProp(e, 'name')) return e.name;
  if (isRecord(e)) {
    const ctor = (e as { constructor?: unknown }).constructor;
    if (typeof ctor === 'function') {
      const ctorName = ctor.name;
      if (typeof ctorName === 'string' && ctorName) return ctorName;
    }
  }
  return 'Error';
}

function getErrMessage(e: unknown): string {
  if (e instanceof Error && typeof e.message === 'string') return e.message;
  if (typeof e === 'string') return e; // casos de throw 'algo'
  if (hasStringProp(e, 'message')) return e.message;
  return 'Unexpected error';
}

@Catch()
export class DomainExceptionFilter implements ExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const res = ctx.getResponse<Response>();
    const req = ctx.getRequest<Request>();
    if (exception instanceof HttpException) {
      const status = exception.getStatus();
      const body = exception.getResponse();
      return res
        .status(status)
        .json(
          typeof body === 'string'
            ? { statusCode: status, message: body }
            : body,
        );
    }
    const name = getErrName(exception);
    const message = getErrMessage(exception);
    const status =
      DOMAIN_ERROR_STATUS[name] ?? HttpStatus.INTERNAL_SERVER_ERROR;
    return res.status(status).json({
      statusCode: status,
      error: name,
      message,
      path: req.url,
      timestamp: new Date().toISOString(),
    });
  }
}
