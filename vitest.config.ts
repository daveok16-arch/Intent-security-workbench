import { defineConfig } from 'vitest/config';
import os from 'os';
import path from 'path';

// Tests must not read or write the developer's runtime snapshot. The store
// persists every mutation to `storage/db/workbench-state.json` by default and
// rehydrates it on construction, so records written by one test file were
// restored on the next run — making the suite pass on a clean checkout and fail
// on a re-run (evidence assertions saw stale records alongside their own).
// Redirecting PERSISTENCE_DIR to a per-run temp directory keeps the persistence
// code path exercised while isolating it from the repository.
const testPersistenceDir = path.join(
  os.tmpdir(),
  `intent-workbench-test-state-${process.pid}`
);

export default defineConfig({
  test: {
    testTimeout: 30000,
    hookTimeout: 30000,
    env: {
      PERSISTENCE_DIR: testPersistenceDir,
    },
  },
});
