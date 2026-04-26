import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { IconDeviceDesktop } from '@tabler/icons-react';
import api from '../api';
import Card from '../components/Card';
import Alert from '../components/Alert';
import Button from '../components/Button';
import ConfirmDialog from '../components/ConfirmDialog';
import Paginator from '../components/Paginator';
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

interface SessionList {
  items: Session[];
  total: number;
}

const PAGE_SIZE = 10;

const SessionsPage: React.FC = () => {
  const [offset, setOffset] = useState(0);
  const { data, refetch } = useQuery<SessionList>({
    queryKey: ['sessions', offset],
    queryFn: () =>
      api.get(`/sessions?limit=${PAGE_SIZE}&offset=${offset}`).then((res) => res.data.data),
  });
  const sessions = data?.items;
  const total = data?.total ?? 0;
  const [error, setError] = useState('');
  const [revokingAll, setRevokingAll] = useState(false);
  const [confirmTarget, setConfirmTarget] = useState<'others' | Session | null>(null);
  const [revokedId, setRevokedId] = useState<string | null>(null);

  const doRevokeOthers = async () => {
    setConfirmTarget(null);
    setError('');
    setRevokingAll(true);
    try {
      await api.post('/sessions/revoke-others');
      setOffset(0);
      refetch();
    } catch (err: unknown) {
      setError(extractError(err, 'Failed to revoke other sessions.'));
    } finally {
      setRevokingAll(false);
    }
  };

  const doRevoke = async (s: Session) => {
    setConfirmTarget(null);
    setError('');
    try {
      await api.delete(`/sessions/${s.id}`);
      if (s.is_current) {
        window.location.assign('/oauth2/logout');
        return;
      }
      setRevokedId(s.id);
      setTimeout(() => {
        setRevokedId(null);
        refetch();
      }, 600);
    } catch (err: unknown) {
      setError(extractError(err, 'Failed to revoke session.'));
    }
  };

  const handleRevoke = (s: Session) => {
    if (s.is_current) {
      setConfirmTarget(s);
    } else {
      doRevoke(s);
    }
  };

  return (
    <>
      <Card
        title="Active Sessions"
        description="Browsers and devices where you are currently signed in."
        action={
          total > 1 ? (
            <Button onClick={() => setConfirmTarget('others')} disabled={revokingAll}>
              {revokingAll ? 'Signing out…' : 'Sign out all other sessions'}
            </Button>
          ) : undefined
        }
      >
        {error && <Alert type="danger" message={error} className="mb-3" />}
        <div className="divide-y divide-theme-fg/10 mt-1">
          {sessions?.map((s) => (
            <div key={s.id} className={`py-4 flex items-center justify-between gap-4 transition-colors duration-500 ${revokedId === s.id ? 'bg-theme-success-bg/15' : ''}`}>
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
                variant="ghost"
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
        <Paginator offset={offset} limit={PAGE_SIZE} total={total} onPageChange={setOffset} />
      </Card>

      {confirmTarget === 'others' && (
        <ConfirmDialog
          title="Sign out all other sessions"
          message="This will sign out all other devices. Your current session will stay active."
          confirmLabel="Sign out all"
          onConfirm={doRevokeOthers}
          onCancel={() => setConfirmTarget(null)}
        />
      )}

      {confirmTarget !== null && confirmTarget !== 'others' && (
        <ConfirmDialog
          title="Sign out current device"
          message="You will be signed out immediately and redirected to the login page."
          confirmLabel="Sign out"
          variant="danger"
          onConfirm={() => doRevoke(confirmTarget)}
          onCancel={() => setConfirmTarget(null)}
        />
      )}
    </>
  );
};

export default SessionsPage;
