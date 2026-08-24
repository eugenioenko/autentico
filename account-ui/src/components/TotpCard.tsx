import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
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
  const { t } = useTranslation();
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
      setError(extractError(err, t('security.disableTotpFailed')));
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
        title={t('security.twoFactorAuth')}
        description={preferredLabel ? t('security.totpPreferred') : t('security.totpApp')}
        action={
          totpEnabled ? (
            <Button
              variant="danger"
              onClick={() => { setShowDisable(!showDisable); setError(''); }}
            >
              {t('security.disable')}
            </Button>
          ) : (
            <Button onClick={() => setShowModal(true)}>
              {t('security.setup')}
            </Button>
          )
        }
      >
        <div className="flex items-center gap-2 mt-1">
          <StatusDot active={totpEnabled} />
          <span className="text-sm text-theme-fg">
            {totpEnabled ? t('security.protectAccount') : t('security.notConfigured')}
          </span>
        </div>
        {showDisable && (
          <form onSubmit={handleDisable} className="mt-4 space-y-3 border-t border-theme-fg/10 pt-4">
            <p className="text-sm text-theme-muted">{t('security.disableTotpMessage')}</p>
            <input
              type="password"
              placeholder={t('profile.currentPassword')}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            {error && <Alert type="danger" message={error} />}
            <div className="flex gap-2">
              <Button type="button" variant="ghost" onClick={() => setShowDisable(false)} className="flex-1">
                {t('common.cancel')}
              </Button>
              <Button type="submit" variant="danger" className="flex-1">
                {t('security.disableTotp')}
              </Button>
            </div>
          </form>
        )}
      </Card>
    </>
  );
};

export default TotpCard;
