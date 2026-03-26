import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { IconKey } from '@tabler/icons-react';
import api from '../api';
import { performPasskeyRegistration } from '../lib/passkey';
import Card from '../components/Card';
import Button from '../components/Button';
import Alert from '../components/Alert';
import StatusDot from '../components/StatusDot';
import TotpSetupModal from '../components/TotpSetupModal';
import { useSettings } from '../context/SettingsContext';
import { useAuth } from '../AuthContext';

interface DeletionRequest {
  id: string;
  user_id: string;
  reason?: string;
  requested_at: string;
}

const SecurityPage: React.FC = () => {
  const settings = useSettings();
  const { logout } = useAuth();
  const queryClient = useQueryClient();

  const { data: mfa, refetch: refetchMfa } = useQuery({
    queryKey: ['mfa'],
    queryFn: () => api.get('/mfa').then((res) => res.data.data),
  });
  const { data: passkeys, refetch: refetchPasskeys } = useQuery({
    queryKey: ['passkeys'],
    queryFn: () => api.get('/passkeys').then((res) => res.data.data),
  });

  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [isChangingPass, setIsChangingPass] = useState(false);
  const [passwordError, setPasswordError] = useState('');
  const [passwordSuccess, setPasswordSuccess] = useState('');

  const [showTotpModal, setShowTotpModal] = useState(false);
  const [mfaDisablePassword, setMfaDisablePassword] = useState('');
  const [showMfaDisable, setShowMfaDisable] = useState(false);
  const [mfaError, setMfaError] = useState('');

  const [addPasskeyError, setAddPasskeyError] = useState('');
  const [isAddingPasskey, setIsAddingPasskey] = useState(false);
  const [deletePasskeyError, setDeletePasskeyError] = useState('');

  const { data: deletionRequest } = useQuery<DeletionRequest | null>({
    queryKey: ['deletion-request'],
    queryFn: () => api.get('/deletion-request').then((res) => res.data.data ?? null),
  });
  const [deletionReason, setDeletionReason] = useState('');
  const [showDeletionConfirm, setShowDeletionConfirm] = useState(false);
  const [deletionSubmitError, setDeletionSubmitError] = useState('');
  const [deletionCancelError, setDeletionCancelError] = useState('');

  const submitDeletionMutation = useMutation({
    mutationFn: () =>
      api.post('/deletion-request', deletionReason.trim() ? { reason: deletionReason.trim() } : {}),
    onSuccess: () => {
      if (settings.allow_self_service_deletion) {
        logout();
        return;
      }
      queryClient.invalidateQueries({ queryKey: ['deletion-request'] });
      setDeletionReason('');
      setShowDeletionConfirm(false);
      setDeletionSubmitError('');
    },
    onError: (err: unknown) => {
      const axiosErr = err as { response?: { data?: { error_description?: string } } };
      setDeletionSubmitError(axiosErr.response?.data?.error_description || 'Failed to submit request.');
    },
  });

  const cancelDeletionMutation = useMutation({
    mutationFn: () => api.delete('/deletion-request'),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['deletion-request'] });
      setDeletionCancelError('');
    },
    onError: (err: unknown) => {
      const axiosErr = err as { response?: { data?: { error_description?: string } } };
      setDeletionCancelError(axiosErr.response?.data?.error_description || 'Failed to cancel request.');
    },
  });

  const handleChangePassword = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setPasswordError('');
    setPasswordSuccess('');
    setIsChangingPass(true);
    try {
      await api.post('/password', { current_password: currentPassword, new_password: newPassword });
      setCurrentPassword('');
      setNewPassword('');
      setPasswordSuccess('Password updated successfully.');
    } catch (err: unknown) {
      const axiosErr = err as { response?: { data?: { error_description?: string } } };
      setPasswordError(axiosErr.response?.data?.error_description || 'Failed to update password.');
    } finally {
      setIsChangingPass(false);
    }
  };

  const handleDeletePasskey = async (id: string) => {
    setDeletePasskeyError('');
    try {
      await api.delete(`/passkeys/${id}`);
      refetchPasskeys();
    } catch (err: unknown) {
      const axiosErr = err as { response?: { data?: { error_description?: string } } };
      setDeletePasskeyError(axiosErr.response?.data?.error_description || 'Failed to delete passkey.');
    }
  };

  const handleDisableMfa = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setMfaError('');
    try {
      await api.delete('/mfa/totp', { data: { current_password: mfaDisablePassword } });
      setShowMfaDisable(false);
      setMfaDisablePassword('');
      refetchMfa();
    } catch (err: unknown) {
      const axiosErr = err as { response?: { data?: { error_description?: string } } };
      setMfaError(axiosErr.response?.data?.error_description || 'Failed to disable 2FA.');
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
        const axiosErr = err as { response?: { data?: { error_description?: string } } };
        setAddPasskeyError(axiosErr.response?.data?.error_description || 'Failed to add passkey.');
      }
    } finally {
      setIsAddingPasskey(false);
    }
  };

  return (
    <div className="space-y-4">
      {showTotpModal && (
        <TotpSetupModal
          onClose={() => setShowTotpModal(false)}
          onSuccess={() => refetchMfa()}
        />
      )}

      <Card title="Password" description="Change your password to keep your account secure.">
        <form onSubmit={handleChangePassword} className="space-y-5 mt-2">
          <div>
            <label>Current Password</label>
            <input
              type="password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
            />
          </div>
          <div>
            <label>New Password</label>
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
            />
          </div>
          {passwordError && <Alert type="danger" message={passwordError} />}
          {passwordSuccess && <Alert type="success" message={passwordSuccess} />}
          <Button type="submit" disabled={isChangingPass || !currentPassword || !newPassword}>
            Update Password
          </Button>
        </form>
      </Card>

      <Card
        title="Two-Factor Authentication"
        description="Authenticator app (TOTP)"
        action={
          mfa?.totp_enabled ? (
            <Button
              variant="danger"
              onClick={() => { setShowMfaDisable(!showMfaDisable); setMfaError(''); }}
              className="text-xs px-3 py-1.5"
            >
              Disable
            </Button>
          ) : (
            <Button onClick={() => setShowTotpModal(true)} className="text-xs px-3 py-1.5">
              Set Up
            </Button>
          )
        }
      >
        <div className="flex items-center gap-2 mt-1">
          <StatusDot active={!!mfa?.totp_enabled} />
          <span className="text-sm text-zinc-700">
            {mfa?.totp_enabled ? 'Protecting your account' : 'Not configured'}
          </span>
        </div>
        {showMfaDisable && (
          <form onSubmit={handleDisableMfa} className="mt-4 space-y-3 border-t border-zinc-100 pt-4">
            <p className="text-sm text-zinc-600">Enter your password to confirm disabling 2FA.</p>
            <input
              type="password"
              placeholder="Current password"
              value={mfaDisablePassword}
              onChange={(e) => setMfaDisablePassword(e.target.value)}
            />
            {mfaError && <Alert type="danger" message={mfaError} />}
            <div className="flex gap-2">
              <Button type="button" variant="ghost" onClick={() => setShowMfaDisable(false)} className="flex-1">
                Cancel
              </Button>
              <Button type="submit" variant="danger" className="flex-1">
                Disable 2FA
              </Button>
            </div>
          </form>
        )}
      </Card>

      <Card
        title="Passkeys"
        description="Biometrics or security keys for passwordless login."
        action={
          <Button onClick={handleAddPasskey} disabled={isAddingPasskey} className="text-xs px-3 py-1.5">
            {isAddingPasskey ? 'Registering…' : 'Add Passkey'}
          </Button>
        }
      >
        {addPasskeyError && <Alert type="danger" message={addPasskeyError} className="mb-2" />}
        {deletePasskeyError && <Alert type="danger" message={deletePasskeyError} className="mb-2" />}
        {passkeys && passkeys.length > 0 ? (
          <div className="divide-y divide-zinc-100 mt-1">
            {passkeys.map((pk: { id: string; name: string; created_at: string }) => (
              <div key={pk.id} className="py-3.5 flex items-center justify-between gap-4">
                <div className="flex items-center gap-3 min-w-0">
                  <div className="w-8 h-8 rounded-full bg-zinc-100 flex items-center justify-center flex-shrink-0">
                    <IconKey size={14} className="text-zinc-700" />
                  </div>
                  <div>
                    <p className="text-sm font-semibold">{pk.name || 'Unnamed Passkey'}</p>
                    <p className="text-xs text-zinc-600">
                      Added {new Date(pk.created_at).toLocaleDateString()}
                    </p>
                  </div>
                </div>
                <Button
                  variant="danger"
                  onClick={() => handleDeletePasskey(pk.id)}
                  className="text-xs px-3 py-1.5 flex-shrink-0"
                >
                  Remove
                </Button>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-sm text-zinc-600 mt-1">No passkeys registered yet.</p>
        )}
      </Card>

      <Card
        title="Danger Zone"
        description={
          settings.allow_self_service_deletion
            ? 'Permanently delete your account. This action cannot be undone.'
            : 'Request account deletion. An admin will review and process your request.'
        }
      >
        {deletionRequest ? (
          <div className="mt-2 space-y-4">
            <div className="rounded-xl bg-red-50 border border-red-200 px-4 py-3 text-sm text-red-700">
              A deletion request was submitted on{' '}
              <strong>{new Date(deletionRequest.requested_at).toLocaleDateString()}</strong>.
              {settings.allow_self_service_deletion
                ? ' Your account has been deleted.'
                : ' An admin will review and process your request. Your account remains active until then.'}
            </div>
            {deletionRequest.reason && (
              <p className="text-sm text-zinc-600">
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
        ) : !showDeletionConfirm ? (
          <div className="mt-2">
            <Button variant="danger" onClick={() => setShowDeletionConfirm(true)}>
              {settings.allow_self_service_deletion ? 'Delete My Account' : 'Request Account Deletion'}
            </Button>
          </div>
        ) : (
          <div className="mt-2 space-y-4 border-t border-zinc-100 pt-4">
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
                value={deletionReason}
                onChange={(e) => setDeletionReason(e.target.value)}
              />
            </div>
            {deletionSubmitError && <Alert type="danger" message={deletionSubmitError} />}
            <div className="flex gap-2">
              <Button
                variant="ghost"
                onClick={() => { setShowDeletionConfirm(false); setDeletionSubmitError(''); }}
                className="flex-1"
              >
                Cancel
              </Button>
              <Button
                variant="danger"
                onClick={() => submitDeletionMutation.mutate()}
                disabled={submitDeletionMutation.isPending}
                className="flex-1"
              >
                {submitDeletionMutation.isPending
                  ? 'Submitting…'
                  : settings.allow_self_service_deletion
                  ? 'Delete Account'
                  : 'Submit Request'}
              </Button>
            </div>
          </div>
        )}
      </Card>
    </div>
  );
};

export default SecurityPage;
