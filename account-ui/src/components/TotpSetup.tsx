import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { QRCodeSVG } from 'qrcode.react';
import { IconCopy, IconCheck } from '@tabler/icons-react';
import api from '../api';
import Modal from './Modal';
import Button from './Button';
import Alert from './Alert';
import { extractError } from '../lib/utils';

interface TotpSetupModalProps {
  onClose: () => void;
  onSuccess: () => void;
}

const TotpSetupModal: React.FC<TotpSetupModalProps> = ({ onClose, onSuccess }) => {
  const { t } = useTranslation();
  const [step, setStep] = useState<'password' | 'loading' | 'qr' | 'verify'>('password');
  const [secret, setSecret] = useState('');
  const [qrData, setQrData] = useState('');
  const [code, setCode] = useState('');
  const [password, setPassword] = useState('');
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState('');
  const [isVerifying, setIsVerifying] = useState(false);

  const beginSetup = (pw: string) => {
    setStep('loading');
    setError('');
    api.post('/mfa/totp/setup', { current_password: pw })
      .then((res) => {
        setSecret(res.data.data.secret);
        setQrData(res.data.data.qr_code_data);
        setStep('qr');
      })
      .catch((err) => {
        setError(extractError(err, t('security.totpSetupFailed')));
        setStep('password');
      });
  };

  const handlePasswordSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    beginSetup(password);
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(secret).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsVerifying(true);
    try {
      await api.post('/mfa/totp/verify', { code });
      onSuccess();
      onClose();
    } catch (err: unknown) {
      setError(extractError(err, t('security.invalidCode')));
    } finally {
      setIsVerifying(false);
    }
  };

  return (
    <Modal title={t('security.setupAuthenticator')} onClose={onClose}>
          {step === 'password' && (
            <form onSubmit={handlePasswordSubmit} className="space-y-4">
              <p className="text-sm text-theme-muted">
                {t('security.setupTotpMessage')}
              </p>
              <div>
                <label>{t('security.password')}</label>
                <input
                  type="password"
                  placeholder={t('security.enterPassword')}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoFocus
                />
              </div>
              {error && <Alert type="danger" message={error} />}
              <div className="flex gap-2">
                <Button type="button" variant="ghost" onClick={onClose} className="flex-1">
                  {t('common.cancel')}
                </Button>
                <Button type="submit" className="flex-1">
                  {t('common.continue')}
                </Button>
              </div>
            </form>
          )}

          {step === 'loading' && (
            <div className="flex justify-center py-8">
              <div className="w-6 h-6 border-2 border-theme-fg/20 border-t-theme-fg rounded-full animate-spin" />
            </div>
          )}

          {step === 'qr' && (
            <div className="space-y-5">
              <p className="text-sm text-theme-muted">
                {t('security.scanQrCode')}
              </p>
              {qrData && (
                <div className="flex justify-center p-4 bg-theme-body rounded-xl">
                  <QRCodeSVG value={qrData} size={180} />
                </div>
              )}
              <div>
                <p className="text-xs text-theme-muted mb-1.5">{t('security.orManualCode')}</p>
                <div className="flex items-center gap-2 px-3 py-2 bg-theme-body rounded-lg border border-theme-fg/15">
                  <code className="flex-1 text-xs font-mono text-theme-fg break-all">{secret}</code>
                  <button onClick={handleCopy} className="flex-shrink-0 text-theme-muted hover:text-theme-fg transition-colors">
                    {copied ? <IconCheck size={15} className="text-theme-success" /> : <IconCopy size={15} />}
                  </button>
                </div>
              </div>
              <Button className="w-full" onClick={() => setStep('verify')}>
                {t('common.continue')}
              </Button>
            </div>
          )}

          {step === 'verify' && (
            <form onSubmit={handleVerify} className="space-y-4">
              <p className="text-sm text-theme-muted">
                {t('security.enterVerificationCode')}
              </p>
              <div>
                <label>{t('security.verificationCode')}</label>
                <input
                  type="text"
                  inputMode="numeric"
                  pattern="[0-9]{6}"
                  maxLength={6}
                  placeholder="000000"
                  value={code}
                  onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
                  autoFocus
                />
              </div>
              {error && <Alert type="danger" message={error} />}
              <div className="flex gap-2">
                <Button type="button" variant="ghost" onClick={() => setStep('qr')} className="flex-1">
                  {t('common.back')}
                </Button>
                <Button type="submit" disabled={code.length !== 6 || isVerifying} className="flex-1">
                  {isVerifying ? t('security.verifying') : t('security.enableTotp')}
                </Button>
              </div>
            </form>
          )}
    </Modal>
  );
};

export default TotpSetupModal;
