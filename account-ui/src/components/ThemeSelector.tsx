import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { IconSun, IconMoon, IconDeviceDesktop } from '@tabler/icons-react';

type Mode = '' | 'light' | 'dark';

const STORAGE_KEY = 'autentico-theme';

const ThemeSelector: React.FC = () => {
  const { t } = useTranslation();
  const [mode, setMode] = useState<Mode>(() => (localStorage.getItem(STORAGE_KEY) ?? '') as Mode);

  const options: { value: Mode; icon: React.FC<{ size?: number }>; label: string }[] = [
    { value: '',      icon: IconDeviceDesktop, label: t('theme.system') },
    { value: 'light', icon: IconSun,           label: t('theme.light') },
    { value: 'dark',  icon: IconMoon,          label: t('theme.dark') },
  ];

  useEffect(() => {
    const root = document.documentElement;
    if (mode) {
      root.setAttribute('data-theme', mode);
      localStorage.setItem(STORAGE_KEY, mode);
    } else {
      root.removeAttribute('data-theme');
      localStorage.removeItem(STORAGE_KEY);
    }
  }, [mode]);

  return (
    <div className="flex items-center rounded-brand border border-theme-fg/20 overflow-hidden">
      {options.map(({ value, icon: Icon, label }) => (
        <button
          key={value}
          onClick={() => setMode(value)}
          title={label}
          className={`p-2 transition-colors ${
            mode === value
              ? 'bg-theme-primary-bg text-theme-primary-fg'
              : 'text-theme-muted hover:text-theme-fg hover:bg-theme-fg/5'
          }`}
        >
          <Icon size={16} />
        </button>
      ))}
    </div>
  );
};

export default ThemeSelector;
