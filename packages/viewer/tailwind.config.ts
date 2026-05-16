import type { Config } from 'tailwindcss';

// Design tokens lifted verbatim from landing-page/tailwind.config.ts.
// Keeping them in sync by hand is intentional — the viewer is a separate
// app to preserve landing-page's static-export deploy.
const config: Config = {
  content: ['./app/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: {
          DEFAULT: '#0a1018',
          raised: '#0f1923',
          panel: '#141f2e',
          border: '#1f2d3f',
        },
        ink: {
          DEFAULT: '#e6edf3',
          muted: '#8b9bb0',
          dim: '#5a6b80',
        },
        amber: {
          DEFAULT: '#ff8c42',
          glow: '#ffaa6b',
          deep: '#e0701f',
        },
        cyan: {
          DEFAULT: '#4cc9f0',
          glow: '#7adcf5',
          deep: '#2596be',
        },
        terminal: {
          green: '#7ee787',
          purple: '#d2a8ff',
          red: '#ff7b72',
          yellow: '#f0c674',
        },
        severity: {
          critical: '#ff5470',
          high: '#ff7b72',
          medium: '#f0c674',
          low: '#7adcf5',
          info: '#8b9bb0',
        },
      },
      fontFamily: {
        sans: ['var(--font-sans)', 'system-ui', 'sans-serif'],
        mono: ['var(--font-mono)', 'ui-monospace', 'monospace'],
      },
      animation: {
        'cursor-blink': 'blink 1s steps(2, start) infinite',
        'fade-up': 'fadeUp 0.6s ease-out forwards',
        'glow-pulse': 'glow 3s ease-in-out infinite',
      },
      keyframes: {
        blink: { to: { visibility: 'hidden' } },
        fadeUp: {
          '0%': { opacity: '0', transform: 'translateY(12px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        glow: {
          '0%, 100%': { opacity: '0.5' },
          '50%': { opacity: '1' },
        },
      },
      backgroundImage: {
        grid: "linear-gradient(to right, rgba(255,255,255,0.04) 1px, transparent 1px), linear-gradient(to bottom, rgba(255,255,255,0.04) 1px, transparent 1px)",
        'radial-glow': 'radial-gradient(ellipse at top, rgba(255,140,66,0.12), transparent 60%)',
      },
    },
  },
  plugins: [],
};

export default config;
