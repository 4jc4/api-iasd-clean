export abstract class HashGenerator {
  abstract hash(payload: string): Promise<string>;
  abstract compare(payload: string, hashed: string): Promise<boolean>;
}
