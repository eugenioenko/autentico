import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { IconExternalLink } from '@tabler/icons-react';
import api from '../api';
import Card from './Card';
import Button from './Button';

interface App {
  client_id: string;
  name: string;
  description?: string;
  logo_uri?: string;
  client_uri?: string;
}

const AppLogo: React.FC<{ app: App }> = ({ app }) => {
  const [failed, setFailed] = useState(false);
  if (app.logo_uri && !failed) {
    return (
      <img
        src={app.logo_uri}
        alt=""
        referrerPolicy="no-referrer"
        onError={() => setFailed(true)}
        className="w-9 h-9 rounded-brand object-contain flex-shrink-0"
      />
    );
  }
  return (
    <div className="w-9 h-9 rounded-brand bg-theme-fg/5 flex items-center justify-center text-sm font-semibold text-theme-muted flex-shrink-0">
      {app.name.charAt(0).toUpperCase()}
    </div>
  );
};

const ApplicationsCard: React.FC = () => {
  const { data: apps } = useQuery<App[]>({
    queryKey: ['apps'],
    queryFn: () => api.get('/apps').then((res) => res.data.data),
  });

  if (!apps?.length) return null;

  return (
    <Card title="Applications" description="Apps you can sign in to with this account.">
      <ul className="divide-y divide-theme-fg/10" data-testid="account-apps">
        {apps.map((app) => (
          <li key={app.client_id} className="py-3 flex items-center gap-3">
            <AppLogo app={app} />
            <div className="min-w-0 flex-1">
              <p className="text-sm font-semibold truncate">{app.name}</p>
              {app.description && <p className="text-sm text-theme-muted">{app.description}</p>}
            </div>
            {app.client_uri && (
              <a href={app.client_uri} target="_blank" rel="noopener noreferrer">
                <Button variant="primary">
                  Open <IconExternalLink size={13} />
                </Button>
              </a>
            )}
          </li>
        ))}
      </ul>
    </Card>
  );
};

export default ApplicationsCard;
