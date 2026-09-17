import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import {defineConfig} from 'vite';

export default defineConfig(() => {
  return {
    plugins: [react(), tailwindcss()],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      },
    },
    server: {
      // HMR is disabled in AI Studio via DISABLE_HMR env var.
      // Do not modify—file watching is disabled to prevent flickering during agent edits.
      hmr: process.env.DISABLE_HMR !== 'true',
      // Disable file watching when DISABLE_HMR is true to save CPU during agent edits.
      //
      // When watching is enabled, exclude the directories the workbench writes
      // to at runtime. Acquired target sources land in data/sources/, and
      // evidence/fixture output in storage/ and fixtures/. Without this, cloning
      // a repository triggered a page reload (and a TypeScript cache flush, and
      // a reload for every tsconfig.json inside the cloned tree) in the
      // researcher's browser mid-investigation.
      watch: process.env.DISABLE_HMR === 'true' ? null : {
        ignored: [
          '**/data/**',
          '**/storage/**',
          '**/fixtures/**',
          '**/dist/**',
          '**/.git/**',
        ],
      },
      allowedHosts: ['.prod-runtime.all-hands.dev', 'localhost', '127.0.0.1'],
    },
  };
});
