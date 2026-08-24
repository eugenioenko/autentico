import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
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
  confirmLabel,
  onConfirm,
  onCancel,
}) => {
  const { t } = useTranslation();
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
        setError(t('common.errorOccurred'));
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
          <label>{t('security.password')}</label>
          <input
            type="password"
            placeholder={t('security.enterPassword')}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoFocus
          />
        </div>
        {error && <Alert type="danger" message={error} />}
        <div className="flex gap-2">
          <Button type="button" variant="ghost" onClick={onCancel} className="flex-1">
            {t('common.cancel')}
          </Button>
          <Button type="submit" disabled={isSubmitting} className="flex-1">
            {isSubmitting ? t('security.verifying') : (confirmLabel ?? t('common.confirm'))}
          </Button>
        </div>
      </form>
    </Modal>
  );
};

export default PasswordPrompt;
