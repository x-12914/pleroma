/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // ---- Surfaces — warm-tinted dark grays (zinc family) ----
        // Avoids the pure-#000 look. Tints layered subtly.
        surface: {
          base: '#0a0a0b',
          raised: '#141416',
          card: '#1a1a1d',
          hover: '#22222533',
          inset: '#080809',
          border: '#26262a',
          'border-strong': '#3a3a40',
        },

        // ---- Text — single tinted gray family, four stops ----
        ink: {
          DEFAULT: '#f5f5f6',
          muted: '#a3a3a8',
          subtle: '#71717a',
          dim: '#525258',
          faint: '#3a3a40',
        },

        // ---- Single signature accent: lime / chartreuse ----
        // Deliberately uncommon in security UIs. Suggests "scanning, active"
        // without the alarmist red or generic cyan/purple of typical AI dashboards.
        accent: {
          DEFAULT: '#a3e635',     // lime-400 — the signature
          hi: '#bef264',          // lime-300, brighter hover
          lo: '#84cc16',           // lime-500, deeper press
          subtle: '#a3e6351a',     // 10% — surface tint
          quiet: '#a3e6350d',      // 5% — subtler tint
          border: '#a3e6354d',     // 30% — borders/outlines
          glow: '#a3e63540',       // 25% — focus rings
        },

        // ---- Semantic signal colors (used ONLY for meaning, not decoration) ----
        signal: {
          danger: '#f87171',       // red-400 — Malicious verdict
          'danger-bg': '#f871711a',
          'danger-border': '#f8717140',
          warning: '#fbbf24',      // amber-400 — Suspicious verdict
          'warning-bg': '#fbbf241a',
          'warning-border': '#fbbf2440',
          ok: '#4ade80',           // green-400 — Normal / Safe verdict
          'ok-bg': '#4ade801a',
          'ok-border': '#4ade8040',
        },

        // ---- Legacy aliases — keep cyber-* tokens but desaturate ----
        // Lets older pages render until they're individually refactored.
        // The new redesigned pages should reach for the tokens above instead.
        dark: {
          50: '#f5f5f6', 100: '#e4e4e7', 200: '#c9c9d0', 300: '#a3a3a8',
          400: '#71717a', 500: '#525258', 600: '#3a3a40', 700: '#26262a',
          800: '#1a1a1d', 900: '#141416', 950: '#0a0a0b',
        },
        cyber: {
          red: '#f87171',
          green: '#4ade80',
          yellow: '#fbbf24',
          blue: '#a3e635',     // legacy "info" → maps to new accent
          purple: '#a3e635',   // legacy "secondary" → also maps to accent
        },
      },

      fontFamily: {
        // Geist is the default font here; Inter Tight is a graceful fallback.
        // No more system-font surprise.
        sans: ['"Geist"', '"Inter Tight"', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['"Geist Mono"', '"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'monospace'],
        display: ['"Geist"', '"Inter Tight"', 'sans-serif'],
      },

      fontSize: {
        // Tight display sizing for headings
        '2xs': ['0.625rem', { lineHeight: '0.875rem', letterSpacing: '0.05em' }],
        'display-xl': ['3.5rem',  { lineHeight: '1', letterSpacing: '-0.03em' }],
        'display-lg': ['2.5rem',  { lineHeight: '1.05', letterSpacing: '-0.025em' }],
        'display-md': ['1.875rem',{ lineHeight: '1.1', letterSpacing: '-0.02em' }],
        'display-sm': ['1.5rem',  { lineHeight: '1.15', letterSpacing: '-0.015em' }],
      },

      letterSpacing: {
        'tighter-2': '-0.04em',
        'tighter-3': '-0.06em',
        'micro': '0.08em',
      },

      borderRadius: {
        // Tighter, more refined corners — drop the rounded-3xl excess.
        'card': '0.625rem',   // 10px
        'pill': '999px',
        'soft': '0.375rem',   // 6px for buttons/inputs
      },

      boxShadow: {
        // Tinted shadows that match the background hue, not pure-black opacity.
        'subtle': '0 1px 2px 0 rgb(0 0 0 / 0.4)',
        'panel': '0 8px 24px -8px rgb(0 0 0 / 0.55), 0 2px 4px 0 rgb(0 0 0 / 0.35)',
        'lift': '0 16px 48px -16px rgb(0 0 0 / 0.65), 0 4px 8px 0 rgb(0 0 0 / 0.4)',
        'focus-ring': '0 0 0 3px #a3e63540',
      },

      backgroundImage: {
        // Subtle grid pattern — for hero/empty backgrounds
        'fine-grid': 'linear-gradient(rgb(255 255 255 / 0.025) 1px, transparent 1px), linear-gradient(90deg, rgb(255 255 255 / 0.025) 1px, transparent 1px)',
        // Subtle noise — break flat-ness
        'noise': 'url("data:image/svg+xml;utf8,<svg xmlns=\'http://www.w3.org/2000/svg\' width=\'200\' height=\'200\'><filter id=\'n\'><feTurbulence type=\'fractalNoise\' baseFrequency=\'0.85\' numOctaves=\'2\' seed=\'4\'/><feColorMatrix values=\'0 0 0 0 1  0 0 0 0 1  0 0 0 0 1  0 0 0 0.06 0\'/></filter><rect width=\'100%\' height=\'100%\' filter=\'url(%23n)\'/></svg>")',
      },

      backgroundSize: {
        'grid-sm': '24px 24px',
        'grid-md': '40px 40px',
      },

      transitionTimingFunction: {
        'spring': 'cubic-bezier(0.22, 1, 0.36, 1)',
        'crisp': 'cubic-bezier(0.4, 0, 0.2, 1)',
      },
    },
  },
  plugins: [],
}
