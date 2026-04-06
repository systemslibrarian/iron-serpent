import { defineConfig } from 'vite';

export default defineConfig({
  optimizeDeps: {
    exclude: ['argon2-browser'],
  },
  build: {
    rollupOptions: {
      external: [],
    },
  },
});
