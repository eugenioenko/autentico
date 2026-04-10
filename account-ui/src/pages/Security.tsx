import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { IconKey } from '@tabler/icons-react';
import api from '../api';
import { performPasskeyRegistration } from '../lib/passkey';
import Card from '../components/Card';
import Button from '../components/Button';
import Alert from '../components/Alert';
import TotpCard from '../components/TotpCard';
import EmailOtpCard from '../components/EmailOtpCard';
import StatusDot from '../components/StatusDot';
import PasswordChangeModal from '../components/PasswordChange';
import AccountDeletionModal from '../components/AccountDeletion';
import { extractError } from '../lib/utils';
import { useSettings } from '../context/SettingsContext';

interface DeletionRequest {
  id: string;
  user_id: string;
  reason?: string;
  requested_at: string;
}

const SecurityPage: React.FC = () => {
  const settings = useSettings();
  const queryClient = useQueryClient();

  const { data: mfa, refetch: refetchMfa } = useQuery({
    queryKey: ['mfa'],
    queryFn: () => api.get('/mfa').then((res) => res.data.data),
  });
  const { data: passkeys, refetch: refetchPasskeys } = useQuery({
    queryKey: ['passkeys'],
    queryFn: () => api.get('/passkeys').then((res) => res.data.data),
  });

  const [showPasswordModal, setShowPasswordModal] = useState(false);

  const [addPasskeyError, setAddPasskeyError] = useState('');
  const [isAddingPasskey, setIsAddingPasskey] = useState(false);
  const [deletePasskeyError, setDeletePasskeyError] = useState('');

  const { data: deletionRequest } = useQuery<DeletionRequest | null>({
    queryKey: ['deletion-request'],
    queryFn: () => api.get('/deletion-request').then((res) => res.data.data ?? null),
  });
  const [showDeletionModal, setShowDeletionModal] = useState(false);
  const [deletionCancelError, setDeletionCancelError] = useState('');

  const cancelDeletionMutation = useMutation({
    mutationFn: () => api.delete('/deletion-request'),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['deletion-request'] });
      setDeletionCancelError('');
    },
    onError: (err: unknown) => {
      setDeletionCancelError(extractError(err, 'Failed to cancel request.'));
    },
  });

  const handleDeletePasskey = async (id: string) => {
    setDeletePasskeyError('');
    try {
      await api.delete(`/passkeys/${id}`);
      refetchPasskeys();
    } catch (err: unknown) {
      setDeletePasskeyError(extractError(err, 'Failed to delete passkey.'));
    }
  };

  const handleAddPasskey = async () => {
    setAddPasskeyError('');
    setIsAddingPasskey(true);
    try {
      const beginRes = await api.post('/passkeys/register/begin');
      const data = beginRes.data.data;
      const credential = await performPasskeyRegistration(data);
      await api.post(`/passkeys/register/finish?challenge_id=${data.challenge_id}`, credential);
      refetchPasskeys();
    } catch (err: unknown) {
      if (err instanceof Error && err.message.includes('cancel')) {
        setAddPasskeyError('Passkey registration was cancelled.');
      } else {
        setAddPasskeyError(extractError(err, 'Failed to add passkey.'));
      }
    } finally {
      setIsAddingPasskey(false);
    }
  };

  return (
    <div className="space-y-4">
      {showPasswordModal && <PasswordChangeModal onClose={() => setShowPasswordModal(false)} />}
      <Card
        title="Password"
        description="Change your password to keep your account secure."
        action={
          <Button onClick={() => setShowPasswordModal(true)}>
            Change Password
          </Button>
        }
      />

      {(settings.mfa_method === 'totp' || settings.mfa_method === 'both') && (
        <TotpCard
          totpEnabled={!!mfa?.totp_enabled}
          preferredLabel={settings.mfa_method === 'both'}
          onChanged={refetchMfa}
        />
      )}

      {(settings.mfa_method === 'email' || settings.mfa_method === 'both') && (
        <EmailOtpCard fallbackLabel={settings.mfa_method === 'both'} />
      )}

      <Card
        title="Passkeys"
        description="Biometrics or security keys for passwordless login."
        action={
          <Button onClick={handleAddPasskey} disabled={isAddingPasskey}>
            {isAddingPasskey ? 'Registering…' : 'Add Passkey'}
          </Button>
        }
      >
        {addPasskeyError && <Alert type="danger" message={addPasskeyError} className="mb-2" />}
        {deletePasskeyError && <Alert type="danger" message={deletePasskeyError} className="mb-2" />}
        {passkeys && passkeys.length > 0 ? (
          <div className="divide-y divide-theme-fg/10 mt-1">
            {passkeys.map((pk: { id: string; name: string; created_at: string }) => (
              <div key={pk.id} className="py-3.5 flex items-center justify-between gap-4">
                <div className="flex items-center gap-3 min-w-0">
                  <div className="w-8 h-8 rounded-full bg-theme-body flex items-center justify-center flex-shrink-0">
                    <IconKey size={14} className="text-theme-fg" />
                  </div>
                  <div>
                    <p className="text-sm font-semibold">{pk.name || 'Unnamed Passkey'}</p>
                    <p className="text-xs text-theme-muted">
                      Added {new Date(pk.created_at).toLocaleDateString()}
                    </p>
                  </div>
                </div>
                <Button
                  variant="danger"
                  onClick={() => handleDeletePasskey(pk.id)}
                  className="flex-shrink-0"
                >
                  Remove
                </Button>
              </div>
            ))}
          </div>
        ) : (
          <div className="flex items-center gap-2 mt-1">
            <StatusDot active={false} />
            <span className="text-sm text-theme-fg">No passkeys registered</span>
          </div>
        )}
      </Card>

      {showDeletionModal && <AccountDeletionModal onClose={() => setShowDeletionModal(false)} />}
      <Card
        title="Danger Zone"
        description={
          settings.allow_self_service_deletion
            ? 'Permanently delete your account. This action cannot be undone.'
            : 'Request account deletion. An admin will review and process your request.'
        }
        action={
          !deletionRequest ? (
            <Button variant="danger" onClick={() => setShowDeletionModal(true)}>
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
            {deletionCancelError && <Alert type="danger" message={deletionCancelError} />}
            {!settings.allow_self_service_deletion && (
              <Button
                variant="ghost"
                onClick={() => cancelDeletionMutation.mutate()}
                disabled={cancelDeletionMutation.isPending}
              >
                {cancelDeletionMutation.isPending ? 'Cancelling…' : 'Cancel Deletion Request'}
              </Button>
            )}
          </div>
        )}
      </Card>
    </div>
  );
};

export default SecurityPage;
