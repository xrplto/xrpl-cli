import { defineConfig } from 'tsup';

export default defineConfig([
  {
    entry: ['src/bin/xrpl.ts'],
    format: ['cjs'],
    target: 'node18',
    outDir: 'dist',
    clean: true,
    splitting: false,
    sourcemap: false,
    dts: false,
    shims: false,
    banner: { js: '#!/usr/bin/env node' }
  },
  {
    entry: ['src/lib/*.ts'],
    format: ['cjs'],
    target: 'node18',
    outDir: 'dist',
    clean: false,
    splitting: false,
    sourcemap: false,
    dts: false,
    shims: false
  }
]);
