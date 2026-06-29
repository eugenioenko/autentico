import React from 'react';
import { useTranslation } from 'react-i18next';
import Card from './Card';
import StatusDot from './StatusDot';

interface EmailOtpCardProps {
  fallbackLabel?: boolean;
}

const EmailOtpCard: React.FC<EmailOtpCardProps> = ({ fallbackLabel }) => {
  const { t } = useTranslation();
  return (
    <Card
      title={t('security.emailOtp')}
      description={
        fallbackLabel
          ? t('security.emailOtpFallback')
          : t('security.emailOtpDescription')
      }
    >
      <div className="flex items-center gap-2 mt-1">
        <StatusDot active={true} />
        <span className="text-sm text-theme-fg">{t('security.emailOtpEnabled')}</span>
      </div>
    </Card>
  );
};

export default EmailOtpCard;
