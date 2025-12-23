import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',  // Accept connections from any IP
    port: 5173,
    strictPort: true,
    // Allow Cloudflare tunnel
    hmr: {
      clientPort: 443,
      protocol: 'wss'
    }
  },
  build: {
    // Target modern browsers for smaller bundle
    target: 'esnext',
    // Code splitting for better caching
    rollupOptions: {
      output: {
        manualChunks(id) {
          // Split vendor libraries into separate chunks for better caching
          if (id.includes('node_modules')) {
            if (id.includes('react') || id.includes('react-dom') || id.includes('react-router')) {
              return 'vendor-react';
            }
            if (id.includes('lucide')) return 'vendor-icons';
            if (id.includes('recharts')) return 'vendor-charts';
            if (id.includes('socket.io')) return 'vendor-socket';
            return 'vendor';
          }
        }
      }
    },
    // Adjust chunk size limit
    chunkSizeWarningLimit: 700,
    // CSS optimization
    cssCodeSplit: true
  },
  // Pre-bundle heavy deps
  optimizeDeps: {
    include: ['react', 'react-dom', 'react-router-dom', 'lucide-react']
  }
})
