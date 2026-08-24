import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
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
  const { t } = useTranslation();
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
      setCancelError(extractError(err, t('account.cancelFailed')));
    },
  });

  return (
    <>
      {showModal && <AccountDeletionModal onClose={() => setShowModal(false)} />}
      <Card
        title={t('account.dangerZone')}
        description={
          settings.allow_self_service_deletion
            ? t('account.permanentlyDelete')
            : t('account.requestDeletionDescription')
        }
        action={
          !deletionRequest ? (
            <Button variant="danger" onClick={() => setShowModal(true)}>
              {t('account.deleteAccount')}
            </Button>
          ) : undefined
        }
      >
        {deletionRequest && (
          <div className="space-y-4">
            <div className="rounded-xl bg-theme-danger-bg border border-theme-danger-bg px-4 py-3 text-sm text-theme-danger-fg">
              {t('account.deletionRequestedAt', { date: new Date(deletionRequest.requested_at).toLocaleDateString() })}
              {settings.allow_self_service_deletion
                ? t('account.accountDeleted')
                : t('account.pendingReviewMessage')}
            </div>
            {deletionRequest.reason && (
              <p className="text-sm text-theme-muted">
                <span className="font-medium">{t('account.reasonLabel')}</span> {deletionRequest.reason}
              </p>
            )}
            {cancelError && <Alert type="danger" message={cancelError} />}
            {!settings.allow_self_service_deletion && (
              <Button
                variant="ghost"
                onClick={() => cancelMutation.mutate()}
                disabled={cancelMutation.isPending}
              >
                {cancelMutation.isPending ? t('account.cancelling') : t('account.cancelDeletionRequest')}
              </Button>
            )}
          </div>
        )}
      </Card>
    </>
  );
};

export default DangerZoneCard;
