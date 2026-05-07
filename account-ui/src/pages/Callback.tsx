import React from 'react';
import { useAuth } from 'oidc-js-react';
import Spinner from '../components/Spinner';
import Alert from '../components/Alert';

const Callback: React.FC = () => {
  const { error } = useAuth();

  if (error) {
    return (
      <div className="min-h-dvh flex items-center justify-center bg-theme-body p-4">
        <div className="bg-theme-bg rounded-2xl shadow-sm p-8 max-w-sm w-full space-y-4">
          <Alert type="danger" message={error.message} />
          <button
            onClick={() => window.location.href = '/account'}
            className="w-full inline-flex items-center justify-center px-4 py-2.5 rounded-brand text-sm font-medium bg-theme-primary-bg text-theme-primary-fg hover:opacity-90 transition-all"
          >
            Try Again
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-dvh flex items-center justify-center bg-theme-accent-bg">
      <Spinner />
    </div>
  );
};

export default Callback;
