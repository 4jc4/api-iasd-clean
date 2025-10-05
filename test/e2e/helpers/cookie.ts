export function getCookieValue(
  setCookie: string | string[] | undefined,
  name: string,
): string | null {
  if (!setCookie) return null;
  const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
  const prefix = `${name}=`;
  for (const c of cookies) {
    const parts = c.split(';')[0] ?? '';
    if (parts.startsWith(prefix)) {
      return parts.slice(prefix.length);
    }
  }
  return null;
}
