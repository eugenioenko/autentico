import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { IconLink } from '@tabler/icons-react';
import api from '../api';
import Card from '../components/Card';
import Alert from '../components/Alert';
import Button from '../components/Button';

interface ConnectedProvider {
  id: string;
  provider_id: string;
  provider_name: string;
  email: string;
  created_at: string;
}

const ConnectedProvidersPage: React.FC = () => {
  const { data: providers, refetch } = useQuery({
    queryKey: ['connected-providers'],
    queryFn: () => api.get('/connected-providers').then((res) => res.data.data),
  });
  const [error, setError] = useState('');

  const handleDisconnect = async (id: string) => {
    setError('');
    try {
      await api.delete(`/connected-providers/${id}`);
      refetch();
    } catch (err: unknown) {
      const axiosErr = err as { response?: { data?: { error_description?: string } } };
      setError(axiosErr.response?.data?.error_description || 'Failed to disconnect provider.');
    }
  };

  return (
    <Card
      title="Connected Providers"
      description="External identity providers linked to your account."
    >
      {error && <Alert type="danger" message={error} className="mb-3" />}
      <div className="divide-y divide-theme-fg/10 mt-1">
        {providers?.map((p: ConnectedProvider) => (
          <div key={p.id} className="py-4 flex items-center justify-between gap-4">
            <div className="flex items-center gap-3 min-w-0">
              <div className="w-9 h-9 rounded-full bg-theme-body flex items-center justify-center flex-shrink-0">
                <IconLink size={15} className="text-theme-fg" />
              </div>
              <div className="min-w-0">
                <p className="text-sm font-semibold">{p.provider_name}</p>
                {p.email && <p className="text-xs text-theme-muted">{p.email}</p>}
                <p className="text-[11px] text-theme-muted mt-0.5">
                  Connected {new Date(p.created_at).toLocaleDateString()}
                </p>
              </div>
            </div>
            <Button
              variant="ghost"
              onClick={() => handleDisconnect(p.id)}
              className="flex-shrink-0 text-xs px-3 py-1.5"
            >
              Disconnect
            </Button>
          </div>
        ))}
        {(!providers || providers.length === 0) && (
          <p className="text-sm text-theme-muted py-4">No external providers connected to your account.</p>
        )}
      </div>
    </Card>
  );
};

export default ConnectedProvidersPage;
