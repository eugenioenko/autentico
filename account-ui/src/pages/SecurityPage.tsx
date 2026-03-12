import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { IconKey } from '@tabler/icons-react';
import api from '../api';
import { performPasskeyRegistration } from '../lib/passkey';
import Card from '../components/Card';
import Button from '../components/Button';
import Alert from '../components/Alert';
import StatusDot from '../components/StatusDot';
import TotpSetupModal from '../components/TotpSetupModal';

const SecurityPage: React.FC = () => {
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
    </div>
  );
};

export default SecurityPage;
