import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      // Permet d'utiliser '@' pour pointer vers 'src' (ex: import X from '@/components/X')
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 5173,
    open: true, // Ouvre automatiquement le navigateur
    hmr: {
      overlay: true, // Affiche les erreurs directement dans l'interface
    },
  },
  build: {
    target: 'esnext', // Cible les navigateurs modernes pour un code plus léger et rapide
    minify: 'esbuild', // Beaucoup plus rapide que 'terser' (par défaut)
    cssCodeSplit: true, // Sépare le CSS par chunk JS
    sourcemap: false, // Désactivé pour la prod (réduit la taille et protège le code)
    chunkSizeWarningLimit: 1000, // Augmente la limite d'avertissement (utile pour les grosses libs AI/3D)
    rollupOptions: {
      output: {
        // Force la séparation des dépendances node_modules dans un fichier 'vendor'
        // Cela permet au navigateur de mettre en cache les libs (React, etc.) séparément de votre code
        manualChunks: (id) => {
          if (id.includes('node_modules')) {
            return 'vendor';
          }
        },
      },
    },
  },
  esbuild: {
    // Supprime automatiquement les console.log et debugger en production
    drop: ['console', 'debugger'],
  },
});
