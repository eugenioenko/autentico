import React, { useState } from 'react';
import PasswordInput from './PasswordInput';
import api from '../api';
import Card from './Card';
import Button from './Button';
import Alert from './Alert';
import StatusDot from './StatusDot';
import TotpSetupModal from './TotpSetup';
import { extractError } from '../lib/utils';

interface TotpCardProps {
  totpEnabled: boolean;
  preferredLabel?: boolean;
  onChanged: () => void;
}

const TotpCard: React.FC<TotpCardProps> = ({ totpEnabled, preferredLabel, onChanged }) => {
  const [showModal, setShowModal] = useState(false);
  const [showDisable, setShowDisable] = useState(false);
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [isDisabling, setIsDisabling] = useState(false);

  const closeDisable = () => {
    setShowDisable(false);
    setPassword('');
    setCode('');
    setError('');
  };

  const handleDisable = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError('');
    setIsDisabling(true);
    try {
      // RFC 6238 §5.2: account actions require a fresh, unused authenticator code.
      await api.delete('/mfa/totp', { data: { current_password: password, code } });
      closeDisable();
      onChanged();
    } catch (err: unknown) {
      setError(extractError(err, 'Failed to disable 2FA.'));
    } finally {
      setIsDisabling(false);
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
              disabled={isDisabling}
              onClick={() => { if (showDisable) closeDisable(); else setShowDisable(true); }}
            >
              Disable
            </Button>
          ) : (
            <Button onClick={() => setShowModal(true)}>
              Set Up
            </Button>
          )
        }
      >
        <div className="flex items-center gap-2 mt-1">
          <StatusDot active={totpEnabled} />
          <span className="text-sm text-theme-fg">
            {totpEnabled ? 'Protecting your account' : 'Not configured'}
          </span>
        </div>
        {showDisable && (
          <form onSubmit={handleDisable} className="mt-4 space-y-3 border-t border-theme-fg/10 pt-4">
            <p className="text-sm text-theme-muted">
              Enter your current password (if your account has one) and a fresh 6-digit code from your authenticator app to disable 2FA.
            </p>
            <p className="text-sm text-theme-muted">
              Disabling 2FA will sign you out on all devices. Sign in again to continue.
            </p>
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              <div>
                <label htmlFor="totp-disable-password">Current password (if set)</label>
                <PasswordInput
                  id="totp-disable-password" name="password" autoComplete="current-password"
                  placeholder="Current password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  disabled={isDisabling}
                />
              </div>
              <div>
                <label htmlFor="totp-disable-code">Authenticator code</label>
                <input
                  id="totp-disable-code" name="code" type="text" inputMode="numeric"
                  autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} required
                  placeholder="000000"
                  value={code}
                  onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
                  disabled={isDisabling}
                  aria-describedby="totp-disable-code-help"
                />
              </div>
            </div>
            <p id="totp-disable-code-help" className="text-sm text-theme-muted">
              If you just used a code to sign in or set up 2FA, wait for the next code.
            </p>
            {error && <Alert type="danger" message={error} />}
            <div className="flex gap-2">
              <Button type="button" variant="ghost" onClick={closeDisable} disabled={isDisabling} className="flex-1">
                Cancel
              </Button>
              <Button type="submit" variant="danger" disabled={code.length !== 6 || isDisabling} className="flex-1">
                {isDisabling ? 'Disabling…' : 'Disable 2FA'}
              </Button>
            </div>
          </form>
        )}
      </Card>
    </>
  );
};

export default TotpCard;
