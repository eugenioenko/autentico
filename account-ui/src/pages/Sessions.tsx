import { useState, useRef, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery } from '@tanstack/react-query';
import { IconDeviceDesktop, IconCircleCheck } from '@tabler/icons-react';
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
  const { t } = useTranslation();
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
  const flashTimer = useRef<ReturnType<typeof setTimeout>>(null);

  useEffect(() => {
    return () => { if (flashTimer.current) clearTimeout(flashTimer.current); };
  }, []);

  const doRevokeOthers = async () => {
    setConfirmTarget(null);
    setError('');
    setRevokingAll(true);
    try {
      await api.post('/sessions/revoke-others');
      setOffset(0);
      refetch();
    } catch (err: unknown) {
      setError(extractError(err, t('sessions.revokeFailed')));
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
      flashTimer.current = setTimeout(() => {
        setRevokedId(null);
        refetch();
      }, 1200);
    } catch (err: unknown) {
      setError(extractError(err, t('sessions.revokeSessionFailed')));
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
        title={t('sessions.activeSessions')}
        description={t('sessions.description')}
        action={
          total > 1 ? (
            <Button onClick={() => setConfirmTarget('others')} disabled={revokingAll}>
              {revokingAll ? t('sessions.signingOut') : t('sessions.revokeAllOthers')}
            </Button>
          ) : undefined
        }
      >
        {error && <Alert type="danger" message={error} className="mb-3" />}
        <div className="divide-y divide-theme-fg/10 mt-1">
          {sessions?.map((s) => (
            <div key={s.id} className={`py-4 flex items-center justify-between gap-4 transition-colors duration-1000 ${revokedId === s.id ? 'bg-theme-success-bg/15' : ''}`}>
              <div className="flex items-center gap-3 min-w-0">
                <div className="w-9 h-9 rounded-full bg-theme-body flex items-center justify-center flex-shrink-0">
                  <IconDeviceDesktop size={15} className="text-theme-fg" />
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <p className="text-sm font-semibold">{describeUserAgent(s.user_agent)}</p>
                    {s.is_current && (
                      <span className="px-1.5 py-0.5 rounded-full text-[10px] font-bold tracking-wider uppercase bg-theme-accent-bg text-theme-accent-fg">
                        {t('sessions.current')}
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-theme-muted leading-snug">
                    {s.ip_address || t('sessions.unknownLocation')}
                    {' · '}
                    {t('sessions.active')} {new Date(s.last_activity_at).toLocaleString()}
                  </p>
                  <p className="text-[11px] text-theme-muted mt-0.5">
                    {formatActiveAppsCount(s.active_apps_count)}
                  </p>
                </div>
              </div>
              {revokedId === s.id ? (
                <IconCircleCheck size={28} stroke={1} className="flex-shrink-0 text-theme-success mr-3" />
              ) : (
                <Button
                  variant="ghost"
                  onClick={() => handleRevoke(s)}
                  className="flex-shrink-0 text-xs"
                >
                  {s.is_current ? t('sessions.signOut') : t('sessions.revoke')}
                </Button>
              )}
            </div>
          ))}
          {(!sessions || sessions.length === 0) && (
            <p className="text-sm text-theme-muted py-4">{t('sessions.noSessions')}</p>
          )}
        </div>
        <Paginator offset={offset} limit={PAGE_SIZE} total={total} onPageChange={setOffset} />
      </Card>

      {confirmTarget === 'others' && (
        <ConfirmDialog
          title={t('sessions.revokeAllOthersTitle')}
          message={t('sessions.revokeAllOthersMessage')}
          confirmLabel={t('sessions.revokeAll')}
          onConfirm={doRevokeOthers}
          onCancel={() => setConfirmTarget(null)}
        />
      )}

      {confirmTarget !== null && confirmTarget !== 'others' && (
        <ConfirmDialog
          title={t('sessions.revokeCurrentTitle')}
          message={t('sessions.revokeCurrentMessage')}
          confirmLabel={t('sessions.signOut')}
          variant="danger"
          onConfirm={() => doRevoke(confirmTarget)}
          onCancel={() => setConfirmTarget(null)}
        />
      )}
    </>
  );
};

export default SessionsPage;
