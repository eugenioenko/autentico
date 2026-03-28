import { Link } from 'react-router-dom';
import { cn } from '../lib/utils';

interface SidebarItemProps {
  to: string;
  icon: React.FC<{ size?: number; stroke?: number }>;
  label: string;
  active?: boolean;
}

const SidebarItem: React.FC<SidebarItemProps> = ({ to, icon: Icon, label, active }) => (
  <Link
    to={to}
    className={cn(
      'flex items-center gap-3 px-3 py-2.5 rounded-brand text-sm font-medium transition-all',
      active ? 'bg-theme-accent-fg text-theme-accent-bg shadow-sm' : 'text-theme-accent-fg/70 hover:text-theme-accent-fg hover:bg-theme-accent-fg/10'
    )}
  >
    <Icon size={16} stroke={1} />
    {label}
  </Link>
);

export default SidebarItem;
