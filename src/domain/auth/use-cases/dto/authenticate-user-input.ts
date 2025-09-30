export interface AuthenticateInput {
  email: string;
  password: string;
  createdByIp?: string | null;
  userAgent?: string | null;
}
