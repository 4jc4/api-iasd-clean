import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
} from '@nestjs/common';
import { z } from 'zod';
import { CreateUserUseCase } from '@domain/users/use-cases/create-user.use-case';
import { Role } from '@domain/users/enums/role.enum';
import { ZodValidationPipe } from '@/app/http/validation/zod-validation.pipe';
import { JwtAuthGuard } from '@/app/http/auth/jwt-auth.guard';
import { RolesGuard } from '@/app/http/auth/roles.guard';
import { Roles } from '@/app/http/auth/roles.decorator';
import { CurrentUser } from '@/app/http/auth/current-user.decorator';

const roleValues = [Role.ADMIN, Role.USER] as const;
const roleSchema = z.enum(roleValues);
const createUserSchema = z.object({
  email: z.email(),
  name: z.string().min(1),
  password: z.string().min(6),
  role: roleSchema.optional(),
});

type CreateUserDto = z.infer<typeof createUserSchema>;

@Controller('users')
@UseGuards(JwtAuthGuard, RolesGuard)
export class UsersController {
  constructor(private readonly createUser: CreateUserUseCase) {}

  @Post()
  @Roles('ADMIN')
  @HttpCode(HttpStatus.CREATED)
  async create(
    @Body(new ZodValidationPipe(createUserSchema)) body: CreateUserDto,
    @CurrentUser()
    user: { sub: string; role: 'ADMIN' | 'USER' },
  ) {
    const result = await this.createUser.execute({
      requestingUserRole: user.role as Role,
      email: body.email,
      name: body.name,
      password: body.password,
      role: body.role,
    });
    return { user: result.user };
  }
}
