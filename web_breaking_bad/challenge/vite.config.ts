import path from 'path'; // Use default import for path module
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [
    react(), // Enables React Fast Refresh
  ],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'), // Shortcut for the src directory
    },
  },
  optimizeDeps: {
    include: ['react-chartjs-2', 'chart.js', 'lucide-react'], // Pre-bundle these dependencies
  },
  build: {
    outDir: 'dist', // Output directory for the production build
    sourcemap: true, // Generate sourcemaps for debugging
    rollupOptions: {
      input: {
        main: path.resolve(__dirname, 'src/main.tsx'), // Main entry point
      },
      output: {
        manualChunks(id) {
          if (id.includes('node_modules')) {
            return id
              .toString()
              .split('node_modules/')[1]
              .split('/')[0]
              .toString();
          }
        },
      },
    },
  },
  server: {
    host: true, // Enable access from the network
    port: 5173, // Default Vite dev server port
  },
});