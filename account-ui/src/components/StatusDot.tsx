import { cn } from '../lib/utils';

const StatusDot = ({ active }: { active: boolean }) => (
  <span
    className={cn(
      'inline-block w-2 h-2 rounded-full flex-shrink-0',
      active ? 'bg-emerald-500' : 'bg-zinc-300'
    )}
  />
);

export default StatusDot;
