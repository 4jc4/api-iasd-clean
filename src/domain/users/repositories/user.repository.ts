import { User } from '@domain/users/entities/user.entity';

export abstract class UserRepository {
  abstract findById(id: string): Promise<User | null>;
  abstract findByEmail(emailRaw: string): Promise<User | null>;
  abstract save(user: User): Promise<void>;
  abstract deleteById(id: string): Promise<boolean>;
}
