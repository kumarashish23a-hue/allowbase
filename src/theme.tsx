import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';

export type Theme = 'light' | 'dark' | 'negative';

const STORAGE_KEY = 'dcp-theme';

const ThemeContext = createContext<{ theme: Theme; setTheme: (theme: Theme) => void }>({
  theme: 'light',
  setTheme: () => {},
});

function getInitialTheme(): Theme {
  if (typeof window === 'undefined') return 'light';
  const stored = window.localStorage.getItem(STORAGE_KEY);
  return stored === 'dark' || stored === 'negative' || stored === 'light' ? stored : 'light';
}

/** Browser chrome (mobile address bar etc.) color per theme. */
const metaThemeColors: Record<Theme, string> = {
  light: '#faf9f6',
  dark: '#080b10',
  negative: '#120e08',
};

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setTheme] = useState<Theme>(getInitialTheme);

  useEffect(() => {
    const root = document.documentElement;
    root.classList.remove('light', 'dark', 'negative');
    root.classList.add(theme);
    // Keeps native form controls, scrollbars, etc. in sync with the theme.
    root.style.colorScheme = theme === 'light' ? 'light' : 'dark';
    document
      .querySelector('meta[name="theme-color"]')
      ?.setAttribute('content', metaThemeColors[theme]);
    try {
      window.localStorage.setItem(STORAGE_KEY, theme);
    } catch {
      // Private mode etc. — theme just won't persist.
    }
  }, [theme]);

  return <ThemeContext.Provider value={{ theme, setTheme }}>{children}</ThemeContext.Provider>;
}

export function useTheme() {
  return useContext(ThemeContext);
}

/** Ambient hero backdrop colors per theme. */
export const vantaThemeColors: Record<Theme, { background: number; color: number }> = {
  light: { background: 0xfaf9f6, color: 0x0f766e },
  dark: { background: 0x080b10, color: 0x22d3ee },
  negative: { background: 0x120e08, color: 0xf9492b },
};

/** Recharts palette per theme (dashboards can't read CSS vars). */
export const chartPalette: Record<
  Theme,
  {
    tick: string;
    tickSoft: string;
    area: string;
    bar: string;
    barGreen: string;
    blocked: string;
    risk: [string, string, string];
    legend: string;
  }
> = {
  light: {
    tick: '#57534e',
    tickSoft: '#706d68',
    area: '#0f766e',
    bar: '#0f766e',
    barGreen: '#367c73',
    blocked: '#1c1917',
    risk: ['#0f766e', '#99958f', '#1c1917'],
    legend: '#115e59',
  },
  dark: {
    tick: '#94a3b8',
    tickSoft: '#64748b',
    area: '#22d3ee',
    bar: '#22d3ee',
    barGreen: '#34d399',
    blocked: '#f87171',
    risk: ['#34d399', '#f59e0b', '#f87171'],
    legend: '#67e8f9',
  },
  negative: {
    tick: '#6c5c47',
    tickSoft: '#978266',
    area: '#dd2c11',
    bar: '#f9492b',
    barGreen: '#fa6996',
    blocked: '#23d9d9',
    risk: ['#fa6996', '#2688f9', '#23d9d9'],
    legend: '#981706',
  },
};
