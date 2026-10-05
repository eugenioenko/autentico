import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { IconChevronRight, IconExternalLink } from '@tabler/icons-react';
import api from '../api';
import Card from '../components/Card';
import Button from '../components/Button';
import StatusDot from '../components/StatusDot';
import { cn } from '../lib/utils';

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

const Dashboard: React.FC = () => {
  const { data: profile } = useQuery({
    queryKey: ['profile'],
    queryFn: () => api.get('/profile').then((res) => res.data.data),
  });
  const { data: mfa } = useQuery({
    queryKey: ['mfa'],
    queryFn: () => api.get('/mfa').then((res) => res.data.data),
  });
  const { data: apps } = useQuery<App[]>({
    queryKey: ['apps'],
    queryFn: () => api.get('/apps').then((res) => res.data.data),
  });

  return (
    <div className="space-y-4" data-testid="account-dashboard">
      <Card
        title="Account Security"
        action={
          <Link to="/security">
            <Button variant="primary">
              Manage <IconChevronRight size={13} />
            </Button>
          </Link>
        }
      >
        <div className="flex items-center gap-2 mt-1">
          <StatusDot active={!!mfa?.totp_enabled} />
          <span className="text-sm">
            Two-factor authentication{' '}
            <span className={cn('font-semibold', mfa?.totp_enabled ? 'text-theme-success' : 'text-theme-muted')}>
              {mfa?.totp_enabled ? 'enabled' : 'not configured'}
            </span>
          </span>
        </div>
      </Card>

      <Card
        title="Profile"
        action={
          <Link to="/profile">
            <Button variant="primary">
              Update <IconChevronRight size={13} />
            </Button>
          </Link>
        }
      >
        <dl className="space-y-3 mt-1">
          {[
            { label: 'Username', value: profile?.username },
            { label: 'Email', value: profile?.email || '—' },
          ].map((row) => (
            <div key={row.label} className="flex justify-between items-center">
              <dt className="text-sm text-theme-muted">{row.label}</dt>
              <dd className="text-sm font-semibold">{row.value}</dd>
            </div>
          ))}
        </dl>
      </Card>

      {!!apps?.length && (
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
                    <Button variant="ghost">
                      Open <IconExternalLink size={13} />
                    </Button>
                  </a>
                )}
              </li>
            ))}
          </ul>
        </Card>
      )}
    </div>
  );
};

export default Dashboard;
