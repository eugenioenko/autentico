import React, { useState } from 'react';
import Modal from './Modal';
import Button from './Button';
import Alert from './Alert';

interface PasswordPromptProps {
  title: string;
  message: string;
  confirmLabel?: string;
  onConfirm: (password: string) => Promise<void>;
  onCancel: () => void;
}

const PasswordPrompt: React.FC<PasswordPromptProps> = ({
  title,
  message,
  confirmLabel = 'Confirm',
  onConfirm,
  onCancel,
}) => {
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsSubmitting(true);
    try {
      await onConfirm(password);
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('An error occurred.');
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <Modal title={title} onClose={onCancel}>
      <form onSubmit={handleSubmit} className="space-y-4">
        <p className="text-sm text-theme-muted">{message}</p>
        <div>
          <label>Password</label>
          <input
            type="password"
            placeholder="Enter your password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoFocus
          />
        </div>
        {error && <Alert type="danger" message={error} />}
        <div className="flex gap-2">
          <Button type="button" variant="ghost" onClick={onCancel} className="flex-1">
            Cancel
          </Button>
          <Button type="submit" disabled={isSubmitting} className="flex-1">
            {isSubmitting ? 'Verifying...' : confirmLabel}
          </Button>
        </div>
      </form>
    </Modal>
  );
};

export default PasswordPrompt;
