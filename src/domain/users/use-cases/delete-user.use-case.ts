import { UserRepository } from '@domain/users/repositories/user.repository';
import { UserNotFoundError } from '@domain/users/errors/user.errors';

export interface DeleteUserInput {
  userId: string;
}

export class DeleteUserUseCase {
  constructor(private readonly users: UserRepository) {}

  async exec({ userId }: DeleteUserInput): Promise<void> {
    const deleted = await this.users.deleteById(userId);
    if (!deleted) {
      throw new UserNotFoundError(userId);
    }
  }
}
