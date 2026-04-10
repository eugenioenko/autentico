import React from 'react';
import { useQuery } from '@tanstack/react-query';
import api from '../api';
import PasswordCard from '../components/PasswordCard';
import TotpCard from '../components/TotpCard';
import EmailOtpCard from '../components/EmailOtpCard';
import PasskeyCard from '../components/PasskeyCard';
import DangerZoneCard from '../components/DangerZoneCard';
import { useSettings } from '../context/SettingsContext';

const SecurityPage: React.FC = () => {
  const settings = useSettings();

  const showTotp = settings.mfa_method === 'totp' || settings.mfa_method === 'both';
  const showEmailOtp = settings.mfa_method === 'email' || settings.mfa_method === 'both';

  const { data: mfa, refetch: refetchMfa } = useQuery({
    queryKey: ['mfa'],
    queryFn: () => api.get('/mfa').then((res) => res.data.data),
  });

  return (
    <div className="space-y-4">
      <PasswordCard />

      {showTotp && (
        <TotpCard
          totpEnabled={!!mfa?.totp_enabled}
          preferredLabel={settings.mfa_method === 'both'}
          onChanged={refetchMfa}
        />
      )}

      {showEmailOtp && (
        <EmailOtpCard fallbackLabel={settings.mfa_method === 'both'} />
      )}

      <PasskeyCard />
      <DangerZoneCard />
    </div>
  );
};

export default SecurityPage;
