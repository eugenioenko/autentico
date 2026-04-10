import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import api from '../api';
import { extractError } from '../lib/utils';
import { useSettings } from '../context/SettingsContext';
import Card from './Card';
import Button from './Button';
import Alert from './Alert';
import AccountDeletionModal from './AccountDeletion';

interface DeletionRequest {
  id: string;
  user_id: string;
  reason?: string;
  requested_at: string;
}

const DangerZoneCard: React.FC = () => {
  const settings = useSettings();
  const queryClient = useQueryClient();

  const { data: deletionRequest } = useQuery<DeletionRequest | null>({
    queryKey: ['deletion-request'],
    queryFn: () => api.get('/deletion-request').then((res) => res.data.data ?? null),
  });

  const [showModal, setShowModal] = useState(false);
  const [cancelError, setCancelError] = useState('');

  const cancelMutation = useMutation({
    mutationFn: () => api.delete('/deletion-request'),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['deletion-request'] });
      setCancelError('');
    },
    onError: (err: unknown) => {
      setCancelError(extractError(err, 'Failed to cancel request.'));
    },
  });

  return (
    <>
      {showModal && <AccountDeletionModal onClose={() => setShowModal(false)} />}
      <Card
        title="Danger Zone"
        description={
          settings.allow_self_service_deletion
            ? 'Permanently delete your account. This action cannot be undone.'
            : 'Request account deletion. An admin will review and process your request.'
        }
        action={
          !deletionRequest ? (
            <Button variant="danger" onClick={() => setShowModal(true)}>
              Delete Account
            </Button>
          ) : undefined
        }
      >
        {deletionRequest && (
          <div className="space-y-4">
            <div className="rounded-xl bg-theme-danger-bg border border-theme-danger-bg px-4 py-3 text-sm text-theme-danger-fg">
              A deletion request was submitted on{' '}
              <strong>{new Date(deletionRequest.requested_at).toLocaleDateString()}</strong>.
              {settings.allow_self_service_deletion
                ? ' Your account has been deleted.'
                : ' An admin will review and process your request. Your account remains active until then.'}
            </div>
            {deletionRequest.reason && (
              <p className="text-sm text-theme-muted">
                <span className="font-medium">Reason:</span> {deletionRequest.reason}
              </p>
            )}
            {cancelError && <Alert type="danger" message={cancelError} />}
            {!settings.allow_self_service_deletion && (
              <Button
                variant="ghost"
                onClick={() => cancelMutation.mutate()}
                disabled={cancelMutation.isPending}
              >
                {cancelMutation.isPending ? 'Cancelling…' : 'Cancel Deletion Request'}
              </Button>
            )}
          </div>
        )}
      </Card>
    </>
  );
};

export default DangerZoneCard;
