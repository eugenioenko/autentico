import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { IconChevronRight, IconExternalLink } from '@tabler/icons-react';
import api from '../api';
import Card from '../components/Card';
import Button from '../components/Button';
import StatusDot from '../components/StatusDot';
import { cn } from '../lib/utils';

const Dashboard: React.FC = () => {
  const { data: apps, isLoading: appsLoading, isError: appsError } = useQuery<{ client_id: string; client_name: string; open_url?: string }[]>({
    queryKey: ['apps'],
    queryFn: () => api.get('/apps').then((res) => res.data.data),
  });
  const { data: profile } = useQuery({
    queryKey: ['profile'],
    queryFn: () => api.get('/profile').then((res) => res.data.data),
  });
  const { data: mfa } = useQuery({
    queryKey: ['mfa'],
    queryFn: () => api.get('/mfa').then((res) => res.data.data),
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

      <Card title="Applications" description="Apps you can sign in to with this account.">
        {appsLoading && <p className="text-sm text-theme-muted py-3">Loading applications…</p>}
        {appsError && <p className="text-sm text-theme-muted py-3">Could not load applications.</p>}
        <ul className="divide-y divide-theme-fg/10">
          {apps?.map((app) => (
            <li key={app.client_id} className="py-3 flex items-center justify-between gap-4">
              <span className="text-sm font-medium">{app.client_name}</span>
              {app.open_url && (
                <a
                  href={app.open_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1.5 px-3 py-2 rounded-brand text-sm font-medium text-theme-muted hover:text-theme-fg hover:bg-theme-fg/5"
                >
                  Open <IconExternalLink size={14} />
                </a>
              )}
            </li>
          ))}
        </ul>
        {apps?.length === 0 && (
          <p className="text-sm text-theme-muted py-3">No applications are available.</p>
        )}
      </Card>
    </div>
  );
};

export default Dashboard;
