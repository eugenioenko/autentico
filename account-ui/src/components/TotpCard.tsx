import React, { useState } from 'react';
import api from '../api';
import Card from './Card';
import Button from './Button';
import Alert from './Alert';
import StatusDot from './StatusDot';
import TotpSetupModal from './TotpSetupModal';

interface TotpCardProps {
  totpEnabled: boolean;
  preferredLabel?: boolean;
  onChanged: () => void;
}

const TotpCard: React.FC<TotpCardProps> = ({ totpEnabled, preferredLabel, onChanged }) => {
  const [showModal, setShowModal] = useState(false);
  const [showDisable, setShowDisable] = useState(false);
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  const handleDisable = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError('');
    try {
      await api.delete('/mfa/totp', { data: { current_password: password } });
      setShowDisable(false);
      setPassword('');
      onChanged();
    } catch (err: unknown) {
      const axiosErr = err as { response?: { data?: { error_description?: string } } };
      setError(axiosErr.response?.data?.error_description || 'Failed to disable 2FA.');
    }
  };

  return (
    <>
      {showModal && (
        <TotpSetupModal
          onClose={() => setShowModal(false)}
          onSuccess={onChanged}
        />
      )}
      <Card
        title="Two-Factor Authentication"
        description={preferredLabel ? 'Authenticator app (TOTP) — preferred method' : 'Authenticator app (TOTP)'}
        action={
          totpEnabled ? (
            <Button
              variant="danger"
              onClick={() => { setShowDisable(!showDisable); setError(''); }}
              className="text-xs px-3 py-1.5"
            >
              Disable
            </Button>
          ) : (
            <Button onClick={() => setShowModal(true)} className="text-xs px-3 py-1.5">
              Set Up
            </Button>
          )
        }
      >
        <div className="flex items-center gap-2 mt-1">
          <StatusDot active={totpEnabled} />
          <span className="text-sm text-zinc-700">
            {totpEnabled ? 'Protecting your account' : 'Not configured'}
          </span>
        </div>
        {showDisable && (
          <form onSubmit={handleDisable} className="mt-4 space-y-3 border-t border-zinc-100 pt-4">
            <p className="text-sm text-zinc-600">Enter your password to confirm disabling 2FA.</p>
            <input
              type="password"
              placeholder="Current password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            {error && <Alert type="danger" message={error} />}
            <div className="flex gap-2">
              <Button type="button" variant="ghost" onClick={() => setShowDisable(false)} className="flex-1">
                Cancel
              </Button>
              <Button type="submit" variant="danger" className="flex-1">
                Disable 2FA
              </Button>
            </div>
          </form>
        )}
      </Card>
    </>
  );
};

export default TotpCard;
