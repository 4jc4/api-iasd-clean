import { BadRequestException, Injectable, PipeTransform } from '@nestjs/common';
import { z, ZodType } from 'zod';

@Injectable()
export class ZodValidationPipe implements PipeTransform<unknown, unknown> {
  constructor(private readonly schema: ZodType) {}

  transform(value: unknown): unknown {
    const result = this.schema.safeParse(value);
    if (!result.success) {
      const tree = z.treeifyError(result.error);
      throw new BadRequestException({
        message: 'Validation failed',
        issues: result.error.issues,
        tree,
      });
    }
    return result.data;
  }
}
