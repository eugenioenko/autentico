import { useId, useState, type ComponentProps } from 'react';
import { IconEye, IconEyeOff } from '@tabler/icons-react';
import { cn } from '../lib/utils';

type PasswordInputProps = Omit<ComponentProps<'input'>, 'type'>;

export default function PasswordInput({ id, className, disabled, ...props }: PasswordInputProps) {
  const generatedId = useId();
  const inputId = id ?? generatedId;
  // NIST SP 800-63B §5.1.1.2: offer an opt-in display of the entered secret.
  const [revealed, setRevealed] = useState(false);

  return (
    <div className="relative">
      <input {...props} id={inputId} disabled={disabled} type={revealed ? 'text' : 'password'} className={cn('pr-12', className)} />
      <button
        type="button"
        aria-label={revealed ? 'Hide password' : 'Show password'}
        aria-pressed={revealed}
        aria-controls={inputId}
        disabled={disabled}
        onClick={() => setRevealed(value => !value)}
        className="absolute right-1 top-1/2 -translate-y-1/2 p-2 rounded-brand text-theme-muted hover:text-theme-fg focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-theme-highlight disabled:opacity-40 disabled:cursor-not-allowed"
      >
        {revealed ? <IconEyeOff size={20} aria-hidden="true" /> : <IconEye size={20} aria-hidden="true" />}
      </button>
    </div>
  );
}
