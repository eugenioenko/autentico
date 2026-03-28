import React from 'react';
import { cn } from '../lib/utils';

type ButtonProps = React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'primary' | 'danger' | 'ghost';
};

const variants = {
  primary: 'bg-theme-primary-bg text-theme-primary-fg hover:opacity-90 shadow-sm',
  danger: 'bg-theme-danger-bg text-theme-danger-fg hover:opacity-90',
  ghost: 'text-theme-muted hover:text-theme-fg hover:bg-theme-fg/5',
};

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = 'primary', ...props }, ref) => (
    <button
      ref={ref}
      className={cn(
        'inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-brand text-sm font-medium',
        'transition-all active:scale-[0.97] disabled:opacity-40 disabled:cursor-not-allowed',
        variants[variant],
        className
      )}
      {...props}
    />
  )
);

Button.displayName = 'Button';
export default Button;
