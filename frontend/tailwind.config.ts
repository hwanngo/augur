import type { Config } from 'tailwindcss';

export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    fontFamily: {
      sans: ['DM Sans', 'ui-sans-serif', 'system-ui', '-apple-system', 'Arial', 'sans-serif'],
      mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'Liberation Mono', 'Courier New', 'monospace'],
    },
    extend: {
      colors: {
        bg: '#0d1117',
        panel: '#161b22',
        border: '#30363d',
        fg: '#e6edf3',
        muted: '#8b949e',
        accent: '#3fb950',
        focus: '#3898ec',
        sev: {
          critical: { bg: '#71221c', fg: '#ffb4ab' },
          high:     { bg: '#7a4a00', fg: '#ffd28a' },
          medium:   { bg: '#39402a', fg: '#d8e08a' },
          low:      { bg: '#23364a', fg: '#9fc7ef' },
        },
      },
    },
  },
  plugins: [],
} satisfies Config;
