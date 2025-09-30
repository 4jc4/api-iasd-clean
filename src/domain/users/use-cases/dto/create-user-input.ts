import { Role } from '@domain/users/enums/role.enum';

export interface CreateUserUseCaseInput {
  email: string;
  name: string;
  password: string;
  requestingUserRole: Role;
  role?: Role;
}
