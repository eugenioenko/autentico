import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery } from '@tanstack/react-query';
import { IconKey } from '@tabler/icons-react';
import api from '../api';
import { performPasskeyRegistration } from '../lib/passkey';
import { extractError } from '../lib/utils';
import Card from './Card';
import Button from './Button';
import Alert from './Alert';
import StatusDot from './StatusDot';
import PasswordPrompt from './PasswordPrompt';

const PasskeyCard: React.FC = () => {
  const { t } = useTranslation();
  const { data: passkeys, refetch } = useQuery({
    queryKey: ['passkeys'],
    queryFn: () => api.get('/passkeys').then((res) => res.data.data),
  });

  const [addError, setAddError] = useState('');
  const [deleteError, setDeleteError] = useState('');
  const [isAdding, setIsAdding] = useState(false);
  const [showAddPrompt, setShowAddPrompt] = useState(false);
  const [showDeletePrompt, setShowDeletePrompt] = useState<string | null>(null);

  const handleAdd = async (password: string) => {
    setAddError('');
    setIsAdding(true);
    setShowAddPrompt(false);
    try {
      const beginRes = await api.post('/passkeys/register/begin', { current_password: password });
      const data = beginRes.data.data;
      const credential = await performPasskeyRegistration(data);
      await api.post(`/passkeys/register/finish?challenge_id=${data.challenge_id}`, credential);
      refetch();
    } catch (err: unknown) {
      if (err instanceof Error && err.message.includes('cancel')) {
        setAddError(t('security.passkeyRegistrationCancelled'));
      } else {
        setAddError(extractError(err, t('security.addPasskeyFailed')));
      }
    } finally {
      setIsAdding(false);
    }
  };

  const handleDelete = async (password: string) => {
    if (!showDeletePrompt) return;
    setDeleteError('');
    const id = showDeletePrompt;
    setShowDeletePrompt(null);
    try {
      await api.delete(`/passkeys/${id}`, { data: { current_password: password } });
      refetch();
    } catch (err: unknown) {
      setDeleteError(extractError(err, t('security.deletePasskeyFailed')));
    }
  };

  return (
    <>
      {showAddPrompt && (
        <PasswordPrompt
          title={t('security.addPasskey')}
          message={t('security.passkeyRegisterMessage')}
          confirmLabel={t('common.continue')}
          onConfirm={handleAdd}
          onCancel={() => setShowAddPrompt(false)}
        />
      )}
      {showDeletePrompt && (
        <PasswordPrompt
          title={t('security.removePasskey')}
          message={t('security.passkeyRemoveMessage')}
          confirmLabel={t('common.remove')}
          onConfirm={handleDelete}
          onCancel={() => setShowDeletePrompt(null)}
        />
      )}
      <Card
        title={t('security.passkey')}
        description={t('security.passkeyDescription')}
        action={
          <Button onClick={() => setShowAddPrompt(true)} disabled={isAdding} data-testid="add-passkey-btn">
            {isAdding ? t('security.registering') : t('security.addPasskey')}
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
                    <p className="text-sm font-semibold">{pk.name || t('security.unnamedPasskey')}</p>
                    <p className="text-xs text-theme-muted">
                      {t('security.addedAt')} {new Date(pk.created_at).toLocaleDateString()}
                    </p>
                  </div>
                </div>
                <Button
                  variant="danger"
                  onClick={() => setShowDeletePrompt(pk.id)}
                  className="flex-shrink-0"
                >
                  {t('common.remove')}
                </Button>
              </div>
            ))}
          </div>
        ) : (
          <div className="flex items-center gap-2 mt-1">
            <StatusDot active={false} />
            <span className="text-sm text-theme-fg">{t('security.noPasskeys')}</span>
          </div>
        )}
      </Card>
    </>
  );
};

export default PasskeyCard;
