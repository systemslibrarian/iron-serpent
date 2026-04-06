import { defineConfig } from 'vite';

export default defineConfig({
  base: '/crypto-lab-iron-serpent/',
  optimizeDeps: {
    exclude: ['argon2-browser'],
  },
  build: {
    rollupOptions: {
      external: [],
    },
  },
});
