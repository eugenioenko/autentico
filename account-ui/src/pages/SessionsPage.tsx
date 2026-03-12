import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { IconHistory } from '@tabler/icons-react';
import api from '../api';
import Card from '../components/Card';
import Alert from '../components/Alert';
import Button from '../components/Button';

interface Session {
  id: string;
  user_agent: string;
  ip_address: string;
  last_activity_at: string | null;
  created_at: string;
  is_current: boolean;
}

const SessionsPage: React.FC = () => {
  const { data: sessions, refetch } = useQuery({
    queryKey: ['sessions'],
    queryFn: () => api.get('/sessions').then((res) => res.data.data),
  });
  const [error, setError] = useState('');

  const handleRevoke = async (id: string) => {
    setError('');
    try {
      await api.delete(`/sessions/${id}`);
      refetch();
    } catch (err: unknown) {
      const axiosErr = err as { response?: { data?: { error_description?: string } } };
      setError(axiosErr.response?.data?.error_description || 'Failed to revoke session.');
    }
  };

  return (
    <Card title="Active Sessions" description="Devices where you are currently signed in.">
      {error && <Alert type="danger" message={error} className="mb-3" />}
      <div className="divide-y divide-zinc-100 mt-1">
        {sessions?.map((s: Session) => (
          <div key={s.id} className="py-4 flex items-center justify-between gap-4">
            <div className="flex items-center gap-3 min-w-0">
              <div className="w-9 h-9 rounded-full bg-zinc-100 flex items-center justify-center flex-shrink-0">
                <IconHistory size={15} className="text-zinc-700" />
              </div>
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <p className="text-sm font-semibold">{s.ip_address}</p>
                  {s.is_current && (
                    <span className="px-1.5 py-0.5 rounded-full text-[10px] font-bold tracking-wider uppercase bg-zinc-900 text-white">
                      Current
                    </span>
                  )}
                </div>
                <p className="text-xs text-zinc-600 truncate leading-snug">{s.user_agent}</p>
                {s.last_activity_at && (
                  <p className="text-[11px] text-zinc-500 mt-0.5">
                    Active {new Date(s.last_activity_at).toLocaleString()}
                  </p>
                )}
              </div>
            </div>
            {!s.is_current && (
              <Button variant="ghost" onClick={() => handleRevoke(s.id)} className="flex-shrink-0 text-xs">
                Log out
              </Button>
            )}
          </div>
        ))}
        {(!sessions || sessions.length === 0) && (
          <p className="text-sm text-zinc-600 py-4">No active sessions found.</p>
        )}
      </div>
    </Card>
  );
};

export default SessionsPage;
