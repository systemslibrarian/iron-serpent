import { defineConfig } from 'vite';

export default defineConfig({
  base: '/iron-serpent/',
  optimizeDeps: {
    exclude: ['argon2-browser'],
  },
  build: {
    rollupOptions: {
      external: [],
    },
  },
});
