import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    testTimeout: 30000,
    hookTimeout: 30000,
    // Restrict collection to this repository's own tests. Acquired target
    // sources live under data/sources/ and storage/, and `vitest run` otherwise
    // discovers their test files too — so analysing a repository silently added
    // that repository's tests to this suite, executing untrusted third-party
    // code as part of `npm test` and distorting the pass/fail count.
    include: [
      'tests/**/*.{test,spec}.?(c|m)[jt]s?(x)',
      'src/**/*.{test,spec}.?(c|m)[jt]s?(x)',
    ],
    exclude: [
      '**/node_modules/**',
      '**/dist/**',
      'data/**',
      'storage/**',
      'fixtures/**',
    ],
  },
});
