export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export function isEmailValid(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}
