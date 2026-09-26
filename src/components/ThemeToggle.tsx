import { Contrast, Moon, Sun } from 'lucide-react';
import { useTheme, type Theme } from '../theme';

const options: { value: Theme; label: string; Icon: typeof Sun }[] = [
  { value: 'light', label: 'Light mode', Icon: Sun },
  { value: 'dark', label: 'Dark mode', Icon: Moon },
  { value: 'negative', label: 'Negative mode', Icon: Contrast },
];

export function ThemeToggle() {
  const { theme, setTheme } = useTheme();

  return (
    <div
      role="group"
      aria-label="Color theme"
      className="flex items-center rounded-full border border-line bg-ink-900 p-1 shadow-card"
    >
      {options.map(({ value, label, Icon }) => {
        const active = theme === value;
        return (
          <button
            key={value}
            type="button"
            onClick={() => setTheme(value)}
            aria-label={label}
            aria-pressed={active}
            title={label}
            className={`rounded-full p-1.5 transition ${
              active ? 'bg-ink-700 text-accent-600' : 'text-mist-500 hover:text-mist-200'
            }`}
          >
            <Icon size={15} strokeWidth={2} />
          </button>
        );
      })}
    </div>
  );
}
