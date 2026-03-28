import React from 'react';
import Card from './Card';
import StatusDot from './StatusDot';

interface EmailOtpCardProps {
  fallbackLabel?: boolean;
}

const EmailOtpCard: React.FC<EmailOtpCardProps> = ({ fallbackLabel }) => {
  return (
    <Card
      title="Email One-Time Password"
      description={
        fallbackLabel
          ? 'Email OTP — fallback when TOTP is not set up'
          : 'A one-time code sent to your email at each login'
      }
    >
      <div className="flex items-center gap-2 mt-1">
        <StatusDot active={true} />
        <span className="text-sm text-theme-fg">Active — code sent to your email at login</span>
      </div>
    </Card>
  );
};

export default EmailOtpCard;
