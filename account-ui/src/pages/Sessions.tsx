import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { IconDeviceDesktop } from '@tabler/icons-react';
import api from '../api';
import Card from '../components/Card';
import Alert from '../components/Alert';
import Button from '../components/Button';
import { describeUserAgent, extractError, formatActiveAppsCount } from '../lib/utils';

interface Session {
  id: string;
  user_agent: string;
  ip_address: string;
  last_activity_at: string;
  created_at: string;
  active_apps_count: number;
  is_current: boolean;
}

const SessionsPage: React.FC = () => {
  const { data: sessions, refetch } = useQuery<Session[]>({
    queryKey: ['sessions'],
    queryFn: () => api.get('/sessions').then((res) => res.data.data),
  });
  const [error, setError] = useState('');
  const [revokingAll, setRevokingAll] = useState(false);

  const handleRevokeOthers = async () => {
    const otherCount = sessions?.filter((s) => !s.is_current).length ?? 0;
    if (otherCount === 0) return;
    const ok = window.confirm(
      `Sign out ${otherCount} other device${otherCount === 1 ? '' : 's'}? Your current session will stay active.`,
    );
    if (!ok) return;
    setError('');
    setRevokingAll(true);
    try {
      await api.post('/sessions/revoke-others');
      refetch();
    } catch (err: unknown) {
      setError(extractError(err, 'Failed to revoke other sessions.'));
    } finally {
      setRevokingAll(false);
    }
  };

  const handleRevoke = async (s: Session) => {
    if (s.is_current) {
      const ok = window.confirm(
        'Revoking this device will sign you out immediately. Continue?',
      );
      if (!ok) return;
    }
    setError('');
    try {
      await api.delete(`/sessions/${s.id}`);
      if (s.is_current) {
        // The backend has cleared the IdP cookie; hand off to RP-initiated
        // logout so any other server-side cleanup (and a friendly "signed
        // out" page) runs. Full page navigation is intentional.
        window.location.assign('/oauth2/logout');
        return;
      }
      refetch();
    } catch (err: unknown) {
      setError(extractError(err, 'Failed to revoke session.'));
    }
  };

  return (
    <Card
      title="Active Sessions"
      description="Browsers and devices where you are currently signed in."
    >
      {error && <Alert type="danger" message={error} className="mb-3" />}
      {sessions && sessions.filter((s) => !s.is_current).length > 0 && (
        <div className="mb-2">
          <Button
            variant="danger"
            onClick={handleRevokeOthers}
            disabled={revokingAll}
            className="text-xs"
          >
            {revokingAll ? 'Signing out...' : 'Sign out all other devices'}
          </Button>
        </div>
      )}
      <div className="divide-y divide-theme-fg/10 mt-1">
        {sessions?.map((s) => (
          <div key={s.id} className="py-4 flex items-center justify-between gap-4">
            <div className="flex items-center gap-3 min-w-0">
              <div className="w-9 h-9 rounded-full bg-theme-body flex items-center justify-center flex-shrink-0">
                <IconDeviceDesktop size={15} className="text-theme-fg" />
              </div>
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <p className="text-sm font-semibold">{describeUserAgent(s.user_agent)}</p>
                  {s.is_current && (
                    <span className="px-1.5 py-0.5 rounded-full text-[10px] font-bold tracking-wider uppercase bg-theme-accent-bg text-theme-accent-fg">
                      Current
                    </span>
                  )}
                </div>
                <p className="text-xs text-theme-muted leading-snug">
                  {s.ip_address || 'Unknown location'}
                  {' · '}
                  Active {new Date(s.last_activity_at).toLocaleString()}
                </p>
                <p className="text-[11px] text-theme-muted mt-0.5">
                  {formatActiveAppsCount(s.active_apps_count)}
                </p>
              </div>
            </div>
            <Button
              variant={s.is_current ? 'ghost' : 'ghost'}
              onClick={() => handleRevoke(s)}
              className="flex-shrink-0 text-xs"
            >
              {s.is_current ? 'Sign out' : 'Revoke'}
            </Button>
          </div>
        ))}
        {(!sessions || sessions.length === 0) && (
          <p className="text-sm text-theme-muted py-4">No active sessions found.</p>
        )}
      </div>
    </Card>
  );
};

export default SessionsPage;
