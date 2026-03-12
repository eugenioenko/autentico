import React from 'react';
import { cn } from '../lib/utils';

type ButtonProps = React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'primary' | 'secondary' | 'danger' | 'ghost';
};

const variants = {
  primary: 'bg-zinc-900 text-white hover:bg-zinc-700 shadow-sm',
  secondary: 'bg-white text-zinc-700 border border-zinc-200 hover:bg-zinc-50 shadow-sm',
  danger: 'text-red-500 bg-red-50 hover:bg-red-100',
  ghost: 'text-zinc-700 hover:text-black hover:bg-zinc-100',
};

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = 'primary', ...props }, ref) => (
    <button
      ref={ref}
      className={cn(
        'inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl text-sm font-medium',
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
