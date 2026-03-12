import React, { useState } from 'react';
import { QRCodeSVG } from 'qrcode.react';
import { IconX, IconCopy, IconCheck } from '@tabler/icons-react';
import api from '../api';
import Button from './Button';
import Alert from './Alert';

interface TotpSetupModalProps {
  onClose: () => void;
  onSuccess: () => void;
}

const TotpSetupModal: React.FC<TotpSetupModalProps> = ({ onClose, onSuccess }) => {
  const [step, setStep] = useState<'loading' | 'qr' | 'verify'>('loading');
  const [secret, setSecret] = useState('');
  const [qrData, setQrData] = useState('');
  const [code, setCode] = useState('');
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState('');
  const [isVerifying, setIsVerifying] = useState(false);

  React.useEffect(() => {
    api.post('/mfa/totp/setup')
      .then((res) => {
        setSecret(res.data.data.secret);
        setQrData(res.data.data.qr_code_data);
        setStep('qr');
      })
      .catch(() => {
        setError('Failed to initialize TOTP setup');
        setStep('qr');
      });
  }, []);

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
      const axiosErr = err as { response?: { data?: { error_description?: string } } };
      setError(axiosErr.response?.data?.error_description || 'Invalid code. Please try again.');
    } finally {
      setIsVerifying(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm">
      <div className="bg-white rounded-2xl shadow-xl w-full max-w-sm">
        <div className="flex items-center justify-between px-6 py-4 border-b border-zinc-100">
          <h2 className="text-base font-semibold">Set Up Authenticator</h2>
          <button onClick={onClose} className="text-zinc-400 hover:text-black transition-colors">
            <IconX size={18} />
          </button>
        </div>

        <div className="px-6 py-5">
          {step === 'loading' && (
            <div className="flex justify-center py-8">
              <div className="w-6 h-6 border-2 border-zinc-300 border-t-zinc-900 rounded-full animate-spin" />
            </div>
          )}

          {step === 'qr' && (
            <div className="space-y-5">
              <p className="text-sm text-zinc-600">
                Scan this QR code with your authenticator app (e.g. Google Authenticator, Authy).
              </p>
              {qrData && (
                <div className="flex justify-center p-4 bg-zinc-50 rounded-xl">
                  <QRCodeSVG value={qrData} size={180} />
                </div>
              )}
              <div>
                <p className="text-xs text-zinc-500 mb-1.5">Or enter this code manually:</p>
                <div className="flex items-center gap-2 px-3 py-2 bg-zinc-50 rounded-lg border border-zinc-200">
                  <code className="flex-1 text-xs font-mono text-zinc-800 break-all">{secret}</code>
                  <button onClick={handleCopy} className="flex-shrink-0 text-zinc-400 hover:text-black transition-colors">
                    {copied ? <IconCheck size={15} className="text-emerald-500" /> : <IconCopy size={15} />}
                  </button>
                </div>
              </div>
              <Button className="w-full" onClick={() => setStep('verify')}>
                Continue
              </Button>
            </div>
          )}

          {step === 'verify' && (
            <form onSubmit={handleVerify} className="space-y-4">
              <p className="text-sm text-zinc-600">
                Enter the 6-digit code from your authenticator app to confirm setup.
              </p>
              <div>
                <label>Verification Code</label>
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
                  Back
                </Button>
                <Button type="submit" disabled={code.length !== 6 || isVerifying} className="flex-1">
                  {isVerifying ? 'Verifying…' : 'Enable 2FA'}
                </Button>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
  );
};

export default TotpSetupModal;
