import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'integrations/nextjs/index': 'src/integrations/nextjs/index.ts',
    'adapters/prisma': 'src/adapters/prisma.ts',
  },
  format: ['esm', 'cjs'],
  dts: true,
  sourcemap: true,
  clean: true,
  splitting: true,
  treeshake: true,
  external: ['next-auth', 'next', '@prisma/client'],
});
