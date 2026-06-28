import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import api from '../api';
import Modal from './Modal';
import Button from './Button';
import Alert from './Alert';
import { extractError } from '../lib/utils';

interface PasswordChangeModalProps {
  onClose: () => void;
}

const PasswordChangeModal: React.FC<PasswordChangeModalProps> = ({ onClose }) => {
  const { t } = useTranslation();
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (newPassword !== confirmPassword) {
      setError(t('profile.passwordMismatch'));
      return;
    }
    setIsSubmitting(true);
    try {
      await api.post('/password', { current_password: currentPassword, new_password: newPassword });
      setSuccess(true);
    } catch (err: unknown) {
      setError(extractError(err, t('profile.passwordUpdateFailed')));
    } finally {
      setIsSubmitting(false);
    }
  };

  if (success) {
    return (
      <Modal title={t('profile.changePassword')} onClose={onClose}>
        <div className="space-y-4">
          <Alert type="success" message={t('profile.passwordUpdateSuccess')} />
          <Button className="w-full" onClick={onClose}>
            {t('common.done')}
          </Button>
        </div>
      </Modal>
    );
  }

  return (
    <Modal title={t('profile.changePassword')} onClose={onClose}>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label>{t('profile.currentPassword')}</label>
          <input
            type="password"
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
            autoFocus
          />
        </div>
        <div>
          <label>{t('profile.newPassword')}</label>
          <input
            type="password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
          />
        </div>
        <div>
          <label>{t('profile.confirmNewPassword')}</label>
          <input
            type="password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
          />
        </div>
        {error && <Alert type="danger" message={error} />}
        <div className="flex gap-2">
          <Button type="button" variant="ghost" onClick={onClose} className="flex-1">
            {t('common.cancel')}
          </Button>
          <Button type="submit" disabled={isSubmitting || !currentPassword || !newPassword || !confirmPassword} className="flex-1">
            {isSubmitting ? t('common.updating') : t('profile.updatePassword')}
          </Button>
        </div>
      </form>
    </Modal>
  );
};

export default PasswordChangeModal;
