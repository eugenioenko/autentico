import React, { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import api from '../api';
import Modal from './Modal';
import Button from './Button';
import Alert from './Alert';
import { useAuth } from 'oidc-js-react';
import { extractError } from '../lib/utils';

interface AccountDeletionModalProps {
  onClose: () => void;
  immediateDeletion: boolean;
}

const AccountDeletionModal: React.FC<AccountDeletionModalProps> = ({ onClose, immediateDeletion }) => {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const [confirmUsername, setConfirmUsername] = useState('');
  const [currentPassword, setCurrentPassword] = useState('');
  const [reason, setReason] = useState('');
  const [error, setError] = useState('');

  const username = (user?.claims?.preferred_username as string) ?? '';
  const usernameMatches = confirmUsername === username;

  const mutation = useMutation({
    mutationFn: () =>
      api.post('/deletion-request', {
        reason: reason.trim(),
        ...(immediateDeletion ? { current_password: currentPassword } : {}),
      }),
    onSuccess: (response) => {
      if (response.status === 204) {
        window.location.href = '/oauth2/logout';
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
      title={immediateDeletion ? 'Delete Account' : 'Request Account Deletion'}
      onClose={onClose}
    >
      <div className="space-y-4" data-testid="account-deletion-form">
        <p className="text-sm text-theme-muted">
          {immediateDeletion
            ? 'Are you sure you want to permanently delete your account? This cannot be undone.'
            : 'A deletion request will be submitted for admin review.'}
        </p>
        <div>
          <label htmlFor="deletion-confirm-username">
            Type <span className="font-bold">{username}</span> to confirm
          </label>
          <input
            id="deletion-confirm-username"
            type="text"
            value={confirmUsername}
            onChange={(e) => setConfirmUsername(e.target.value)}
            placeholder={username}
            autoFocus
          />
        </div>
        {immediateDeletion && (
          <div>
            <label htmlFor="deletion-current-password">Current Password</label>
            <input id="deletion-current-password" type="password" autoComplete="current-password"
              value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} />
          </div>
        )}
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
            disabled={!usernameMatches || mutation.isPending || (immediateDeletion && !currentPassword)}
            className="flex-1"
          >
            {mutation.isPending
              ? 'Submitting…'
              : immediateDeletion
                ? 'Delete Account'
                : 'Submit Request'}
          </Button>
        </div>
      </div>
    </Modal>
  );
};

export default AccountDeletionModal;
