export abstract class RandomGenerator {
  abstract randomBytes(size: number): Promise<Uint8Array>;
  abstract toBase64url(bytes: Uint8Array): string;
}
