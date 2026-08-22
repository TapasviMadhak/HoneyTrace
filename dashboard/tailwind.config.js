/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: '#06080d',
          card: '#0d1117',
          border: '#1e2638',
          crimson: '#ff3366',
          cyan: '#00f0ff',
          mint: '#00ff9d',
          panel: 'rgba(13, 17, 23, 0.82)',
          muted: '#8b949e',
        }
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
        sans: ['Inter', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'sans-serif'],
      },
      animation: {
        'radar-ping': 'radar-ping 2s cubic-bezier(0, 0, 0.2, 1) infinite',
        'pulse-glow': 'pulse-glow 2s ease-in-out infinite alternate',
        'beacon-pulse': 'beacon-pulse 1.5s ease-in-out infinite',
      },
      keyframes: {
        'radar-ping': {
          '75%, 100%': {
            transform: 'scale(2.4)',
            opacity: '0',
          },
        },
        'pulse-glow': {
          '0%': { opacity: '0.6', transform: 'scale(0.98)' },
          '100%': { opacity: '1', transform: 'scale(1.02)' },
        },
        'beacon-pulse': {
          '0%, 100%': { transform: 'scale(1)', opacity: '1' },
          '50%': { transform: 'scale(1.4)', opacity: '0.4' },
        },
      }
    },
  },
  plugins: [],
}
