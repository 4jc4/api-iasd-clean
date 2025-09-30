import { Role } from '@domain/users/enums/role.enum';

export interface AuthenticateOutput {
  accessToken: string;
  refreshToken: string;
  user: {
    id: string;
    email: string;
    name: string;
    role: Role;
    createdAt: Date;
    updatedAt: Date;
  };
}
