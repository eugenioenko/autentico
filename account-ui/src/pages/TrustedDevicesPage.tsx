import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { IconDevices } from '@tabler/icons-react';
import api from '../api';
import Card from '../components/Card';
import Button from '../components/Button';

interface TrustedDevice {
  id: string;
  device_name: string;
  created_at: string;
  last_used_at: string;
  expires_at: string;
}

const TrustedDevicesPage: React.FC = () => {
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
      const axiosErr = err as { response?: { data?: { error_description?: string } } };
      setError(axiosErr.response?.data?.error_description || 'Failed to revoke trusted device.');
    }
  };

  return (
    <Card
      title="Trusted Devices"
      description="Devices that skip two-factor authentication prompts."
    >
      {error && <p className="text-red-600 text-sm mb-3">{error}</p>}
      <div className="divide-y divide-zinc-100 mt-1">
        {devices?.map((d: TrustedDevice) => (
          <div key={d.id} className="py-4 flex items-center justify-between gap-4">
            <div className="flex items-center gap-3 min-w-0">
              <div className="w-9 h-9 rounded-full bg-zinc-100 flex items-center justify-center flex-shrink-0">
                <IconDevices size={15} className="text-zinc-700" />
              </div>
              <div className="min-w-0">
                <p className="text-sm font-semibold">{d.device_name || 'Unknown Device'}</p>
                <p className="text-xs text-zinc-600">
                  Last used {new Date(d.last_used_at).toLocaleDateString()}
                </p>
                <p className="text-[11px] text-zinc-500 mt-0.5">
                  Expires {new Date(d.expires_at).toLocaleDateString()}
                </p>
              </div>
            </div>
            <Button variant="danger" onClick={() => handleRevoke(d.id)} className="flex-shrink-0 text-xs px-3 py-1.5">
              Revoke
            </Button>
          </div>
        ))}
        {(!devices || devices.length === 0) && (
          <p className="text-sm text-zinc-600 py-4">No trusted devices. You'll always be prompted for 2FA.</p>
        )}
      </div>
    </Card>
  );
};

export default TrustedDevicesPage;
