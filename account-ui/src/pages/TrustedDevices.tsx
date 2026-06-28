import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery } from '@tanstack/react-query';
import { IconDevices } from '@tabler/icons-react';
import api from '../api';
import Card from '../components/Card';
import Alert from '../components/Alert';
import Button from '../components/Button';
import { extractError } from '../lib/utils';

interface TrustedDevice {
  id: string;
  device_name: string;
  created_at: string;
  last_used_at: string;
  expires_at: string;
}

const TrustedDevicesPage: React.FC = () => {
  const { t } = useTranslation();
  const { data: devices, refetch } = useQuery({
    queryKey: ['trusted-devices'],
    queryFn: () => api.get('/trusted-devices').then((res) => res.data.data),
  });
  const [error, setError] = useState('');

  const handleRevoke = async (id: string) => {
    setError('');
    try {
      await api.delete(`/trusted-devices/${id}`);
      refetch();
    } catch (err: unknown) {
      setError(extractError(err, t('trustedDevices.revokeFailed')));
    }
  };

  return (
    <Card
      title={t('trustedDevices.title')}
      description={t('trustedDevices.skipMfa')}
    >
      {error && <Alert type="danger" message={error} className="mb-3" />}
      <div className="divide-y divide-theme-fg/10 mt-1">
        {devices?.map((d: TrustedDevice) => (
          <div key={d.id} className="py-4 flex items-center justify-between gap-4">
            <div className="flex items-center gap-3 min-w-0">
              <div className="w-9 h-9 rounded-full bg-theme-body flex items-center justify-center flex-shrink-0">
                <IconDevices size={15} className="text-theme-fg" />
              </div>
              <div className="min-w-0">
                <p className="text-sm font-semibold">{d.device_name || t('trustedDevices.unknownDevice')}</p>
                <p className="text-xs text-theme-muted">
                  {t('trustedDevices.lastUsed')} {new Date(d.last_used_at).toLocaleDateString()}
                </p>
                <p className="text-[11px] text-theme-muted mt-0.5">
                  {t('trustedDevices.expiresAt')} {new Date(d.expires_at).toLocaleDateString()}
                </p>
              </div>
            </div>
            <Button variant="danger" onClick={() => handleRevoke(d.id)} className="flex-shrink-0">
              {t('trustedDevices.revoke')}
            </Button>
          </div>
        ))}
        {(!devices || devices.length === 0) && (
          <p className="text-sm text-theme-muted py-4">{t('trustedDevices.noDevicesMessage')}</p>
        )}
      </div>
    </Card>
  );
};

export default TrustedDevicesPage;
