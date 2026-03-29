import React from 'react';
import { IconMenu2 } from '@tabler/icons-react';
import ThemeSelector from './ThemeSelector';

interface AppHeaderProps {
  title: string;
  onMenuOpen: () => void;
}

const AppHeader: React.FC<AppHeaderProps> = ({ title, onMenuOpen }) => (
  <header className="h-16 bg-theme-body flex items-center gap-4 px-5 md:px-8">
    <button
      className="md:hidden text-theme-muted hover:text-theme-fg"
      onClick={onMenuOpen}
    >
      <IconMenu2 size={20} />
    </button>
    <h1 className="text-xl font-bold tracking-tight flex-1">{title}</h1>
    <ThemeSelector />
  </header>
);

export default AppHeader;
