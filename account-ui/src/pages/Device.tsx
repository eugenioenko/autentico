import { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { IconDevices, IconCheck, IconX } from '@tabler/icons-react';
import { useAuth } from 'oidc-js-react';
import api from '../api';
import Alert from '../components/Alert';
import Spinner from '../components/Spinner';

type Status = 'input' | 'loading' | 'confirm' | 'authorized' | 'denied' | 'error';

interface DeviceInfo {
  user_code: string;
  client_name: string;
  scope: string;
}

const scopeDescriptions: Record<string, string> = {
  openid: 'Verify your identity',
  profile: 'View your profile information',
  email: 'View your email address',
  address: 'View your address',
  phone: 'View your phone number',
  offline_access: 'Stay signed in between sessions',
};

export default function DevicePage() {
  const { code } = useParams<{ code: string }>();
  const { user } = useAuth();
  const [status, setStatus] = useState<Status>('input');
  const [userCode, setUserCode] = useState(code ?? '');
  const [deviceInfo, setDeviceInfo] = useState<DeviceInfo | null>(null);
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (code) {
      verifyCode(code);
    }
  }, [code]);

  const verifyCode = async (codeValue: string) => {
    setStatus('loading');
    setError('');
    try {
      const { data } = await api.post('/device/verify', { user_code: codeValue });
      setDeviceInfo(data);
      setUserCode(data.user_code);
      setStatus('confirm');
    } catch (err: any) {
      const msg = err?.response?.data?.error_description || err?.response?.data?.message || 'Invalid or expired code';
      setError(msg);
      setStatus('error');
    }
  };

  const handleSubmitCode = (e: React.FormEvent) => {
    e.preventDefault();
    if (!userCode.trim()) return;
    verifyCode(userCode.trim());
  };

  const handleAuthorize = async () => {
    setSubmitting(true);
    try {
      await api.post('/device/authorize', { user_code: userCode });
      setStatus('authorized');
    } catch (err: any) {
      const msg = err?.response?.data?.error_description || 'Failed to authorize device';
      setError(msg);
      setStatus('error');
    } finally {
      setSubmitting(false);
    }
  };

  const handleDeny = async () => {
    setSubmitting(true);
    try {
      await api.post('/device/deny', { user_code: userCode });
      setStatus('denied');
    } catch (err: any) {
      const msg = err?.response?.data?.error_description || 'Failed to deny device';
      setError(msg);
      setStatus('error');
    } finally {
      setSubmitting(false);
    }
  };

  const scopes = deviceInfo?.scope?.split(' ').filter(Boolean) ?? [];

  return (
    <div className="min-h-dvh flex items-center justify-center bg-theme-body p-4">
      <div className="bg-theme-bg rounded-2xl shadow-sm p-8 max-w-sm w-full space-y-6">
        {status === 'input' && (
          <>
            <div className="text-center space-y-2">
              <IconDevices size={40} className="mx-auto text-theme-primary-bg" />
              <h1 className="text-xl font-semibold text-theme-fg">Link a Device</h1>
              <p className="text-sm text-theme-muted">
                Enter the code displayed on your device.
              </p>
            </div>
            <form onSubmit={handleSubmitCode} className="space-y-6">
              <input
                type="text"
                value={userCode}
                onChange={(e) => setUserCode(e.target.value.toUpperCase())}
                placeholder="XXXX-XXXX"
                maxLength={9}
                autoFocus
              />
              <button
                type="submit"
                disabled={!userCode.trim()}
                className="w-full px-4 py-2.5 rounded-brand text-sm font-medium bg-theme-primary-bg text-theme-primary-fg hover:opacity-90 transition-all disabled:opacity-50"
              >
                Continue
              </button>
            </form>
          </>
        )}

        {status === 'loading' && (
          <div className="flex justify-center py-8">
            <Spinner />
          </div>
        )}

        {status === 'confirm' && deviceInfo && (
          <>
            <div className="text-center space-y-2">
              <IconDevices size={40} className="mx-auto text-theme-primary-bg" />
              <h1 className="text-xl font-semibold text-theme-fg">Authorize Device</h1>
            </div>
            <div className="space-y-4">
              <p className="text-sm text-theme-fg text-center">
                <span className="font-semibold">{deviceInfo.client_name}</span> is requesting access to your account
                {user?.claims?.preferred_username ? (
                  <> as <span className="font-semibold">{String(user.claims.preferred_username)}</span></>
                ) : null}.
              </p>
              <p className="text-2xl text-theme-fg text-center font-mono tracking-widest">{deviceInfo.user_code}</p>
              {scopes.length > 0 && (
                <ul className="divide-y divide-theme-border">
                  {scopes.map((scope) => (
                    <li key={scope} className="py-2.5 text-sm text-theme-fg">
                      {scopeDescriptions[scope] ?? scope}
                    </li>
                  ))}
                </ul>
              )}
            </div>
            <div className="flex gap-3">
              <button
                onClick={handleDeny}
                disabled={submitting}
                className="flex-1 px-4 py-2.5 rounded-brand text-sm font-medium border border-theme-border text-theme-fg hover:bg-theme-body transition-all disabled:opacity-50"
              >
                Deny
              </button>
              <button
                onClick={handleAuthorize}
                disabled={submitting}
                className="flex-1 px-4 py-2.5 rounded-brand text-sm font-medium bg-theme-primary-bg text-theme-primary-fg hover:opacity-90 transition-all disabled:opacity-50"
              >
                Allow
              </button>
            </div>
          </>
        )}

        {status === 'authorized' && (
          <div className="text-center space-y-4">
            <div className="w-12 h-12 rounded-full bg-theme-success-bg flex items-center justify-center mx-auto">
              <IconCheck size={24} className="text-theme-success-fg" />
            </div>
            <h1 className="text-xl font-semibold text-theme-fg">Device Authorized</h1>
            <p className="text-sm text-theme-muted">
              You can return to your device. This page can be closed.
            </p>
          </div>
        )}

        {status === 'denied' && (
          <div className="text-center space-y-4">
            <div className="w-12 h-12 rounded-full bg-theme-danger-bg flex items-center justify-center mx-auto">
              <IconX size={24} className="text-theme-danger-fg" />
            </div>
            <h1 className="text-xl font-semibold text-theme-fg">Access Denied</h1>
            <p className="text-sm text-theme-muted">
              The device will not be granted access.
            </p>
          </div>
        )}

        {status === 'error' && (
          <div className="space-y-4">
            <Alert type="danger" message={error} />
            <button
              onClick={() => { setStatus('input'); setError(''); }}
              className="w-full px-4 py-2.5 rounded-brand text-sm font-medium bg-theme-primary-bg text-theme-primary-fg hover:opacity-90 transition-all"
            >
              Try Again
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
