import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import api from '../api';
import Modal from './Modal';
import Button from './Button';
import Alert from './Alert';
import { useSettings } from '../context/SettingsContext';
import { useAuth } from 'oidc-js-react';
import { extractError } from '../lib/utils';

interface AccountDeletionModalProps {
  onClose: () => void;
}

const AccountDeletionModal: React.FC<AccountDeletionModalProps> = ({ onClose }) => {
  const { t } = useTranslation();
  const settings = useSettings();
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const [confirmUsername, setConfirmUsername] = useState('');
  const [reason, setReason] = useState('');
  const [error, setError] = useState('');

  const username = (user?.claims?.preferred_username as string) ?? '';
  const usernameMatches = confirmUsername === username;

  const mutation = useMutation({
    mutationFn: () =>
      api.post('/deletion-request', reason.trim() ? { reason: reason.trim() } : {}),
    onSuccess: () => {
      if (settings.allow_self_service_deletion) {
        window.location.href = '/oauth2/logout';
        return;
      }
      queryClient.invalidateQueries({ queryKey: ['deletion-request'] });
      onClose();
    },
    onError: (err: unknown) => {
      setError(extractError(err, t('account.submitRequestFailed')));
    },
  });

  return (
    <Modal
      title={settings.allow_self_service_deletion ? t('account.selfServiceDeletion') : t('account.requestDeletion')}
      onClose={onClose}
    >
      <div className="space-y-4">
        <p className="text-sm text-theme-muted">
          {settings.allow_self_service_deletion
            ? t('account.confirmSelfServiceDeletion')
            : t('account.submitForReview')}
        </p>
        <div>
          <label>
            {t('account.typeToConfirmWithUsername', { username: username })}
          </label>
          <input
            type="text"
            value={confirmUsername}
            onChange={(e) => setConfirmUsername(e.target.value)}
            placeholder={username}
            autoFocus
          />
        </div>
        <div>
          <label>
            {t('account.reason')} <span className="text-theme-muted font-normal">{t('account.reasonOptional')}</span>
          </label>
          <textarea
            className="w-full rounded-xl border border-theme-fg/20 px-3 py-2 text-sm resize-none focus:outline-none focus:ring-2 focus:ring-theme-highlight bg-theme-bg text-theme-fg"
            rows={3}
            placeholder={t('account.reasonPlaceholder')}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
          />
        </div>
        {error && <Alert type="danger" message={error} />}
        <div className="flex gap-2">
          <Button type="button" variant="ghost" onClick={onClose} className="flex-1">
            {t('common.cancel')}
          </Button>
          <Button
            variant="danger"
            onClick={() => mutation.mutate()}
            disabled={!usernameMatches || mutation.isPending}
            className="flex-1"
          >
            {mutation.isPending
              ? t('account.submitting')
              : settings.allow_self_service_deletion
                ? t('account.deleteAccount')
                : t('account.submitRequest')}
          </Button>
        </div>
      </div>
    </Modal>
  );
};

export default AccountDeletionModal;
