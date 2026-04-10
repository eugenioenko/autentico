import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { IconKey } from '@tabler/icons-react';
import api from '../api';
import { performPasskeyRegistration } from '../lib/passkey';
import { extractError } from '../lib/utils';
import Card from './Card';
import Button from './Button';
import Alert from './Alert';
import StatusDot from './StatusDot';

const PasskeyCard: React.FC = () => {
  const { data: passkeys, refetch } = useQuery({
    queryKey: ['passkeys'],
    queryFn: () => api.get('/passkeys').then((res) => res.data.data),
  });

  const [addError, setAddError] = useState('');
  const [deleteError, setDeleteError] = useState('');
  const [isAdding, setIsAdding] = useState(false);

  const handleAdd = async () => {
    setAddError('');
    setIsAdding(true);
    try {
      const beginRes = await api.post('/passkeys/register/begin');
      const data = beginRes.data.data;
      const credential = await performPasskeyRegistration(data);
      await api.post(`/passkeys/register/finish?challenge_id=${data.challenge_id}`, credential);
      refetch();
    } catch (err: unknown) {
      if (err instanceof Error && err.message.includes('cancel')) {
        setAddError('Passkey registration was cancelled.');
      } else {
        setAddError(extractError(err, 'Failed to add passkey.'));
      }
    } finally {
      setIsAdding(false);
    }
  };

  const handleDelete = async (id: string) => {
    setDeleteError('');
    try {
      await api.delete(`/passkeys/${id}`);
      refetch();
    } catch (err: unknown) {
      setDeleteError(extractError(err, 'Failed to delete passkey.'));
    }
  };

  return (
    <Card
      title="Passkeys"
      description="Biometrics or security keys for passwordless login."
      action={
        <Button onClick={handleAdd} disabled={isAdding}>
          {isAdding ? 'Registering…' : 'Add Passkey'}
        </Button>
      }
    >
      {addError && <Alert type="danger" message={addError} className="mb-2" />}
      {deleteError && <Alert type="danger" message={deleteError} className="mb-2" />}
      {passkeys && passkeys.length > 0 ? (
        <div className="divide-y divide-theme-fg/10 mt-1">
          {passkeys.map((pk: { id: string; name: string; created_at: string }) => (
            <div key={pk.id} className="py-3.5 flex items-center justify-between gap-4">
              <div className="flex items-center gap-3 min-w-0">
                <div className="w-8 h-8 rounded-full bg-theme-body flex items-center justify-center flex-shrink-0">
                  <IconKey size={14} className="text-theme-fg" />
                </div>
                <div>
                  <p className="text-sm font-semibold">{pk.name || 'Unnamed Passkey'}</p>
                  <p className="text-xs text-theme-muted">
                    Added {new Date(pk.created_at).toLocaleDateString()}
                  </p>
                </div>
              </div>
              <Button
                variant="danger"
                onClick={() => handleDelete(pk.id)}
                className="flex-shrink-0"
              >
                Remove
              </Button>
            </div>
          ))}
        </div>
      ) : (
        <div className="flex items-center gap-2 mt-1">
          <StatusDot active={false} />
          <span className="text-sm text-theme-fg">No passkeys registered</span>
        </div>
      )}
    </Card>
  );
};

export default PasskeyCard;
