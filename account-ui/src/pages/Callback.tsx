import React, { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../AuthContext';
import Spinner from '../components/Spinner';

const Callback: React.FC = () => {
  const { signinCallback, isLoading } = useAuth();
  const navigate = useNavigate();
  const called = React.useRef(false);

  useEffect(() => {
    if (isLoading || called.current) return;
    called.current = true;
    signinCallback().then(() => navigate('/')).catch(() => navigate('/'));
  }, [signinCallback, navigate, isLoading]);

  return (
    <div className="min-h-dvh flex items-center justify-center bg-theme-accent-bg">
      <Spinner />
    </div>
  );
};

export default Callback;
