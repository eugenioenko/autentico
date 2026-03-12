import React from 'react';
import { IconAlertCircle, IconCircleCheck } from '@tabler/icons-react';
import { cn } from '../lib/utils';

type AlertProps = {
  type: 'danger' | 'success';
  message: string;
  className?: string;
};

const config = {
  danger: {
    icon: IconAlertCircle,
    className: 'bg-red-50 border border-red-200 text-red-700',
  },
  success: {
    icon: IconCircleCheck,
    className: 'bg-emerald-50 border border-emerald-200 text-emerald-700',
  },
};

const Alert: React.FC<AlertProps> = ({ type, message, className }) => {
  const { icon: Icon, className: typeClass } = config[type];
  return (
    <div className={cn('flex items-start gap-2.5 rounded-xl px-4 py-3 text-sm', typeClass, className)}>
      <Icon size={16} className="mt-0.5 flex-shrink-0" />
      <span>{message}</span>
    </div>
  );
};

export default Alert;
