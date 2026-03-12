import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { IconChevronRight } from '@tabler/icons-react';
import api from '../api';
import Card from '../components/Card';
import Button from '../components/Button';
import StatusDot from '../components/StatusDot';
import { cn } from '../lib/utils';

const Dashboard: React.FC = () => {
  const { data: profile } = useQuery({
    queryKey: ['profile'],
    queryFn: () => api.get('/profile').then((res) => res.data.data),
  });
  const { data: mfa } = useQuery({
    queryKey: ['mfa'],
    queryFn: () => api.get('/mfa').then((res) => res.data.data),
  });

  return (
    <div className="space-y-4">
      <Card
        title="Account Security"
        action={
          <Link to="/security">
            <Button variant="primary" className="text-xs px-3 py-1.5">
              Manage <IconChevronRight size={13} />
            </Button>
          </Link>
        }
      >
        <div className="flex items-center gap-2 mt-1">
          <StatusDot active={!!mfa?.totp_enabled} />
          <span className="text-sm">
            Two-factor authentication{' '}
            <span className={cn('font-semibold', mfa?.totp_enabled ? 'text-emerald-600' : 'text-zinc-600')}>
              {mfa?.totp_enabled ? 'enabled' : 'not configured'}
            </span>
          </span>
        </div>
      </Card>

      <Card title="Profile">
        <dl className="space-y-3 mt-1">
          {[
            { label: 'Username', value: profile?.username },
            { label: 'Email', value: profile?.email || '—' },
          ].map((row) => (
            <div key={row.label} className="flex justify-between items-center">
              <dt className="text-sm text-zinc-600">{row.label}</dt>
              <dd className="text-sm font-semibold">{row.value}</dd>
            </div>
          ))}
        </dl>
      </Card>
    </div>
  );
};

export default Dashboard;
