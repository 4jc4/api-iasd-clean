import { Role } from '@domain/users/enums/role.enum';

export interface CreateUserUseCaseOutput {
  id: string;
  email: string;
  name: string;
  role: Role;
  createdAt: Date;
  updatedAt: Date;
}
