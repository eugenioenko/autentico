import React, { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import api from '../api';
import Modal from './Modal';
import Button from './Button';
import Alert from './Alert';
import { useSettings } from '../context/SettingsContext';
import { useAuth } from '../AuthContext';
import { extractError } from '../lib/utils';

interface AccountDeletionModalProps {
  onClose: () => void;
}

const AccountDeletionModal: React.FC<AccountDeletionModalProps> = ({ onClose }) => {
  const settings = useSettings();
  const { logout, user } = useAuth();
  const queryClient = useQueryClient();
  const [confirmUsername, setConfirmUsername] = useState('');
  const [reason, setReason] = useState('');
  const [error, setError] = useState('');

  const username = user?.profile?.preferred_username ?? '';
  const usernameMatches = confirmUsername === username;

  const mutation = useMutation({
    mutationFn: () =>
      api.post('/deletion-request', reason.trim() ? { reason: reason.trim() } : {}),
    onSuccess: () => {
      if (settings.allow_self_service_deletion) {
        logout();
        return;
      }
      queryClient.invalidateQueries({ queryKey: ['deletion-request'] });
      onClose();
    },
    onError: (err: unknown) => {
      setError(extractError(err, 'Failed to submit request.'));
    },
  });

  return (
    <Modal
      title={settings.allow_self_service_deletion ? 'Delete Account' : 'Request Account Deletion'}
      onClose={onClose}
    >
      <div className="space-y-4">
        <p className="text-sm text-theme-muted">
          {settings.allow_self_service_deletion
            ? 'Are you sure you want to permanently delete your account? This cannot be undone.'
            : 'A deletion request will be submitted for admin review.'}
        </p>
        <div>
          <label>
            Type <span className="font-bold">{username}</span> to confirm
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
            Reason <span className="text-theme-muted font-normal">(optional)</span>
          </label>
          <textarea
            className="w-full rounded-xl border border-theme-fg/20 px-3 py-2 text-sm resize-none focus:outline-none focus:ring-2 focus:ring-theme-highlight bg-theme-bg text-theme-fg"
            rows={3}
            placeholder="Tell us why you want to delete your account…"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
          />
        </div>
        {error && <Alert type="danger" message={error} />}
        <div className="flex gap-2">
          <Button type="button" variant="ghost" onClick={onClose} className="flex-1">
            Cancel
          </Button>
          <Button
            variant="danger"
            onClick={() => mutation.mutate()}
            disabled={!usernameMatches || mutation.isPending}
            className="flex-1"
          >
            {mutation.isPending
              ? 'Submitting…'
              : settings.allow_self_service_deletion
                ? 'Delete Account'
                : 'Submit Request'}
          </Button>
        </div>
      </div>
    </Modal>
  );
};

export default AccountDeletionModal;
