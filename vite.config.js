import { defineConfig } from 'vite';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = fileURLToPath(new URL('.', import.meta.url));

export default defineConfig(({ command }) => ({
  // In production the bundle is served by Flask under /static/dist/, so
  // url() references inside the built CSS (Font Awesome webfonts, etc.)
  // must be rewritten with that prefix — otherwise the browser asks for
  // /assets/fa-solid-900-*.woff2 and Flask returns 404, breaking icons.
  // Dev keeps `/` because routes/vite.py points the page straight at the
  // Vite dev server on :5173.
  base: command === 'build' ? '/static/dist/' : '/',
  // Build the frontend bundle into static/dist/ so Flask can serve it
  // through the existing /static/ route. The Jinja helper `vite_assets()`
  // (see routes/ui.py) reads .vite/manifest.json to inject hashed asset tags.
  build: {
    outDir: resolve(__dirname, 'static/dist'),
    emptyOutDir: true,
    manifest: true,
    sourcemap: false,
    rollupOptions: {
      input: resolve(__dirname, 'frontend/src/main.js'),
    },
  },
  server: {
    port: 5173,
    strictPort: true,
    origin: 'http://localhost:5173',
    cors: true,
    // Proxy the Flask API so `npm run dev` can serve the SPA shell while
    // /api/* still hits the Python backend on :5000.
    proxy: {
      '/api':    'http://localhost:5000',
      '/static': 'http://localhost:5000',
    },
  },
  resolve: {
    // Force a single jQuery instance so the DataTables plugin attaches to
    // the same object exposed on window.$ in jquery-global.js.
    dedupe: ['jquery'],
  },
}));
