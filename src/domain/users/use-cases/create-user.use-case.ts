import { Role } from '@domain/users/enums/role.enum';
import { User } from '@domain/users/entities/user.entity';
import { UserRepository } from '@domain/users/repositories/user.repository';
import { HashGenerator } from '@domain/shared/services/hash-generator';
import { UuidGenerator } from '@domain/shared/services/uuid-generator';
import { Clock } from '@domain/shared/services/clock';
import {
  EmailAlreadyInUseError,
  UnauthorizedUserError,
} from '@domain/users/errors/user.errors';
import { CreateUserUseCaseInput } from '@domain/users/use-cases/dto/create-user-input';
import { CreateUserUseCaseOutput } from '@domain/users/use-cases/dto/create-user-output';
import { normalizeEmail } from '@domain/shared/utils/email';

export class CreateUserUseCase {
  constructor(
    private readonly userRepository: UserRepository,
    private readonly hashGenerator: HashGenerator,
    private readonly uuidGenerator: UuidGenerator,
    private readonly clock: Clock,
  ) {}

  async execute(
    params: CreateUserUseCaseInput,
  ): Promise<{ user: CreateUserUseCaseOutput }> {
    if (params.requestingUserRole !== Role.ADMIN) {
      throw new UnauthorizedUserError('create new users');
    }
    const normalizedEmail = normalizeEmail(params.email);
    const existing = await this.userRepository.findByEmail(normalizedEmail);
    if (existing) {
      throw new EmailAlreadyInUseError(params.email);
    }
    const passwordHash = await this.hashGenerator.hash(params.password);
    const user = User.create(
      {
        email: normalizedEmail,
        name: params.name,
        passwordHash,
        role: params.role,
      },
      {
        uuid: () => this.uuidGenerator.generate(),
        now: () => this.clock.now(),
      },
    );
    await this.userRepository.save(user);
    return { user: user.toObject() };
  }
}
