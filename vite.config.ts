import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    rolldownOptions: {
      output: {
        // Split heavy third-party libs into their own chunks so the main
        // bundle stays small and browsers can cache them independently.
        manualChunks(id) {
          if (id.includes('node_modules/recharts')) return 'vendor-charts';
          if (id.includes('node_modules/framer-motion')) return 'vendor-motion';
          if (id.includes('node_modules/@supabase')) return 'vendor-supabase';
          if (id.includes('node_modules/three') || id.includes('node_modules/vanta')) return 'vendor-3d';
          if (
            id.includes('node_modules/react-dom') ||
            id.includes('node_modules/react/') ||
            id.includes('node_modules/react-router') ||
            id.includes('node_modules/scheduler')
          ) {
            return 'vendor-react';
          }
          return undefined;
        },
      },
    },
  },
})
