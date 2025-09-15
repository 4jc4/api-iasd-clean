import { pathsToModuleNameMapper } from 'ts-jest';
import { readFileSync } from 'fs';

type TsConfig = { compilerOptions: { paths: Record<string, string[]> } };
const tsconfig = JSON.parse(
  readFileSync('./tsconfig.json', 'utf8'),
) as TsConfig;

export default {
  displayName: 'e2e',
  testEnvironment: 'node',
  rootDir: '.',
  moduleFileExtensions: ['ts', 'js', 'json'],
  transform: { '^.+\\.(t|j)s$': 'ts-jest' },
  testMatch: ['<rootDir>/test/e2e/**/*.e2e.spec.ts'],
  roots: ['<rootDir>/test/e2e'],
  moduleNameMapper: pathsToModuleNameMapper(tsconfig.compilerOptions.paths, {
    prefix: '<rootDir>/src/',
  }),
  collectCoverageFrom: ['src/**/*.ts'],
  testPathIgnorePatterns: ['/node_modules/', '/dist/'],
  maxWorkers: 1,
};
