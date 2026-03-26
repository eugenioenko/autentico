import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import api from '../api';
import Card from '../components/Card';
import Button from '../components/Button';
import Alert from '../components/Alert';
import { useSettings } from '../context/SettingsContext';

interface DeletionRequest {
  id: string;
  user_id: string;
  reason?: string;
  requested_at: string;
}

const DeletionPage: React.FC = () => {
  const settings = useSettings();
  const queryClient = useQueryClient();

  const { data: request, isLoading } = useQuery<DeletionRequest | null>({
    queryKey: ['deletion-request'],
    queryFn: () =>
      api.get('/deletion-request').then((res) => res.data.data ?? null),
  });

  const [reason, setReason] = useState('');
  const [showConfirm, setShowConfirm] = useState(false);
  const [submitError, setSubmitError] = useState('');
  const [cancelError, setCancelError] = useState('');

  const submitMutation = useMutation({
    mutationFn: () =>
      api.post('/deletion-request', reason.trim() ? { reason: reason.trim() } : {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['deletion-request'] });
      setReason('');
      setShowConfirm(false);
      setSubmitError('');
    },
    onError: (err: unknown) => {
      const axiosErr = err as { response?: { data?: { error_description?: string } } };
      setSubmitError(axiosErr.response?.data?.error_description || 'Failed to submit request.');
    },
  });

  const cancelMutation = useMutation({
    mutationFn: () => api.delete('/deletion-request'),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['deletion-request'] });
      setCancelError('');
    },
    onError: (err: unknown) => {
      const axiosErr = err as { response?: { data?: { error_description?: string } } };
      setCancelError(axiosErr.response?.data?.error_description || 'Failed to cancel request.');
    },
  });

  if (isLoading) {
    return (
      <div className="space-y-4">
        <Card title="Account Deletion" description="Manage your account deletion request.">
          <p className="text-sm text-zinc-500">Loading…</p>
        </Card>
      </div>
    );
  }

  if (request) {
    return (
      <div className="space-y-4">
        <Card
          title="Deletion Requested"
          description="Your account is scheduled for deletion."
        >
          <div className="mt-2 space-y-4">
            <div className="rounded-xl bg-red-50 border border-red-200 px-4 py-3 text-sm text-red-700">
              A deletion request was submitted on{' '}
              <strong>{new Date(request.requested_at).toLocaleDateString()}</strong>.
              {settings.allow_self_service_deletion
                ? ' Your account has been deleted.'
                : ' An admin will review and process your request. Your account remains active until then.'}
            </div>
            {request.reason && (
              <p className="text-sm text-zinc-600">
                <span className="font-medium">Reason:</span> {request.reason}
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
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <Card
        title="Delete Account"
        description={
          settings.allow_self_service_deletion
            ? 'Permanently delete your account. This action cannot be undone.'
            : 'Request account deletion. An admin will review and process your request.'
        }
      >
        <div className="mt-2 space-y-4">
          {!showConfirm ? (
            <Button
              variant="danger"
              onClick={() => setShowConfirm(true)}
            >
              {settings.allow_self_service_deletion
                ? 'Delete My Account'
                : 'Request Account Deletion'}
            </Button>
          ) : (
            <div className="space-y-4 border-t border-zinc-100 pt-4">
              <p className="text-sm text-zinc-700 font-medium">
                {settings.allow_self_service_deletion
                  ? 'Are you sure you want to permanently delete your account? This cannot be undone.'
                  : 'A deletion request will be submitted for admin review.'}
              </p>
              <div>
                <label className="block text-sm font-medium text-zinc-700 mb-1">
                  Reason <span className="text-zinc-400 font-normal">(optional)</span>
                </label>
                <textarea
                  className="w-full rounded-xl border border-zinc-200 px-3 py-2 text-sm resize-none focus:outline-none focus:ring-2 focus:ring-zinc-300"
                  rows={3}
                  placeholder="Tell us why you want to delete your account…"
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                />
              </div>
              {submitError && <Alert type="danger" message={submitError} />}
              <div className="flex gap-2">
                <Button
                  variant="ghost"
                  onClick={() => { setShowConfirm(false); setSubmitError(''); }}
                  className="flex-1"
                >
                  Cancel
                </Button>
                <Button
                  variant="danger"
                  onClick={() => submitMutation.mutate()}
                  disabled={submitMutation.isPending}
                  className="flex-1"
                >
                  {submitMutation.isPending
                    ? 'Submitting…'
                    : settings.allow_self_service_deletion
                    ? 'Delete Account'
                    : 'Submit Request'}
                </Button>
              </div>
            </div>
          )}
        </div>
      </Card>
    </div>
  );
};

export default DeletionPage;
