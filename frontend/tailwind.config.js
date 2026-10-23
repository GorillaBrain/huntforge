/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        bg: '#0c0e12', panel: '#12151b', raised: '#181c24', line: '#262b36', 'line-soft': '#1c2029',
        ink: '#e6e8ec', mute: '#9aa3b2', faint: '#667085',
        accent: { DEFAULT: '#4f9cf9', soft: '#14253d' },
        sev: { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#38bdf8', info: '#94a3b8' },
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'Segoe UI', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Consolas', 'monospace'],
      },
      fontSize: { xs: ['12px', '16px'], sm: ['13px', '18px'], base: ['14px', '20px'] },
    },
  },
  plugins: [],
}
