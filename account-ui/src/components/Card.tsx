import React from 'react';

interface CardProps {
  title: string;
  children?: React.ReactNode;
  description?: string;
  action?: React.ReactNode;
}

const Card: React.FC<CardProps> = ({ title, children, description, action }) => (
  <div className="bg-theme-bg rounded-brand shadow-sm overflow-hidden">
    <div className="px-7 py-5 flex items-start justify-between gap-4">
      <div>
        <h3 className="text-base font-semibold">{title}</h3>
        {description && <p className="text-sm text-theme-muted mt-0.5">{description}</p>}
      </div>
      {action && <div className="flex-shrink-0 mt-0.5">{action}</div>}
    </div>
    {children && <div className="px-7 pb-7">{children}</div>}
  </div>
);

export default Card;
