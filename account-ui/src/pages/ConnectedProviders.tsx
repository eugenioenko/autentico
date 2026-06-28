import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery } from '@tanstack/react-query';
import { IconLink } from '@tabler/icons-react';
import api from '../api';
import Card from '../components/Card';
import Alert from '../components/Alert';
import Button from '../components/Button';
import { extractError } from '../lib/utils';

interface ConnectedProvider {
  id: string;
  provider_id: string;
  provider_name: string;
  email: string;
  created_at: string;
}

const ConnectedProvidersPage: React.FC = () => {
  const { t } = useTranslation();
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
      setError(extractError(err, t('connectedProviders.disconnectFailed')));
    }
  };

  return (
    <Card
      title={t('connectedProviders.title')}
      description={t('connectedProviders.providersDescription')}
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
                  {t('connectedProviders.connectedAt')} {new Date(p.created_at).toLocaleDateString()}
                </p>
              </div>
            </div>
            <Button
              variant="ghost"
              onClick={() => handleDisconnect(p.id)}
              className="flex-shrink-0"
            >
              {t('connectedProviders.disconnect')}
            </Button>
          </div>
        ))}
        {(!providers || providers.length === 0) && (
          <p className="text-sm text-theme-muted py-4">{t('connectedProviders.noProvidersMessage')}</p>
        )}
      </div>
    </Card>
  );
};

export default ConnectedProvidersPage;
