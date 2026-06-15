import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    applesauce: 'src/applesauce.ts',
  },
  format: ['esm', 'cjs'],
  dts: true,
  clean: true,
  sourcemap: true,
  minify: false,
  external: ['nostr-tools', 'applesauce-accounts', 'applesauce-signers'],
});
