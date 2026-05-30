import { defineConfig, mergeConfig } from 'vitest/config';
import viteConfig from './vite.config';

export default mergeConfig(
  viteConfig,
  defineConfig({
    test: {
      environment: 'jsdom',
      setupFiles: ['./src/test-setup.ts'],
      globals: true,
      exclude: ['**/node_modules/**', '**/dist/**'],
      server: {
        deps: {
          // Prevent cytoscape (large canvas lib) from being bundled into test workers.
          // Tests that use CytoscapeComponent mock react-cytoscapejs via vi.mock() instead.
          // Setting inline: false makes vitest use native Node.js require() for these
          // packages rather than Vite-transforming them — avoiding the ~4MB parse budget.
          inline: [],
          external: [/cytoscape/, /react-cytoscapejs/],
        },
      },
    },
    optimizeDeps: {
      exclude: ['cytoscape', 'react-cytoscapejs'],
    },
  })
);
