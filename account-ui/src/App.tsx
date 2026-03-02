import React, { useEffect } from 'react';
import { BrowserRouter, Routes, Route, Link, useNavigate, useLocation } from 'react-router-dom';
import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query';
import { User, Shield, Key, History, LogOut, Menu, X } from 'lucide-react';
import { AuthProvider, useAuth } from './AuthContext';
import api from './api';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

const queryClient = new QueryClient();

// --- Components ---

const SidebarItem = ({ to, icon: Icon, label, active }: { to: string, icon: any, label: string, active?: boolean }) => (
  <Link
    to={to}
    className={cn(
      "flex items-center gap-3 px-3 py-2 rounded-sm transition-colors",
      active
        ? "bg-zinc-200 ont-medium"
        : " hover:text-zinc-900 hover:bg-zinc-100"
    )}
  >
    <Icon size={20} />
    <span>{label}</span>
  </Link>
);

const Card = ({ title, children, description }: { title: string, children: React.ReactNode, description?: string }) => (
  <div className="bg-white border border-gray-300 rounded-sm overflow-hidden">
    <div className="px-6 py-4">
      <h3 className="text-lg font-semibold">{title}</h3>
      {description && <p className="text-sm  mt-1">{description}</p>}
    </div>
    <div className="p-6">
      {children}
    </div>
  </div>
);

const Button = React.forwardRef<HTMLButtonElement, React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'primary' | 'secondary' | 'danger' }>(
  ({ className, variant = 'primary', ...props }, ref) => {
    const variants = {
      primary: "bg-black text-white hover:bg-zinc-700",
      danger: "bg-red-600 text-white hover:bg-red-700",
    };
    return (
      <button
        ref={ref}
        className={cn("px-4 py-2 rounded-sm font-medium transition-all active:scale-[0.98] disabled:opacity-50", variants[variant], className)}
        {...props}
      />
    );
  }
);

// --- Pages ---

const Dashboard = () => {
  const { data: profile } = useQuery({ queryKey: ['profile'], queryFn: () => api.get('/profile').then(res => res.data.data) });
  const { data: mfa } = useQuery({ queryKey: ['mfa'], queryFn: () => api.get('/mfa').then(res => res.data.data) });

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <Card title="Account Security">
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Shield className={cn(mfa?.totp_enabled ? "text-green-600" : "text-zinc-400")} />
                <div>
                  <p className="font-medium">Two-factor authentication</p>
                  <p className="text-sm">{mfa?.totp_enabled ? "Enabled" : "Not enabled"}</p>
                </div>
              </div>
              <Link to="/security">
                <Button className="text-sm">Manage</Button>
              </Link>
            </div>
          </div>
        </Card>

        <Card title="Profile">
          <div className="space-y-2">
            <div className="flex justify-between py-2 border-b border-gray-200">
              <span className="">Username</span>
              <span className="font-medium">{profile?.username}</span>
            </div>
            <div className="flex justify-between py-2">
              <span className="">Email</span>
              <span className="font-medium">{profile?.email || 'Not set'}</span>
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
};

const ProfilePage = () => {
  const { data: profile, refetch } = useQuery({ queryKey: ['profile'], queryFn: () => api.get('/profile').then(res => res.data.data) });
  const [email, setEmail] = React.useState('');
  const [isUpdating, setIsUpdating] = React.useState(false);

  useEffect(() => {
    if (profile) setEmail(profile.email || '');
  }, [profile]);

  const handleUpdate = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsUpdating(true);
    try {
      await api.put('/profile', { email });
      refetch();
    } catch (err) {
      console.error(err);
    } finally {
      setIsUpdating(false);
    }
  };

  return (
    <div className="max-w-2xl">
      <Card title="Personal Information" description="Update your email address and profile details.">
        <form onSubmit={handleUpdate} className="space-y-4">
          <div className="space-y-2">
            <label>Username</label>
            <input
              type="text"
              value={profile?.username || ''}
              disabled
            />
          </div>
          <div className="space-y-2">
            <label>Email Address</label>
            <input
              type="email"
              value={email}
              onChange={e => setEmail(e.target.value)}
            />
          </div>
          <Button type="submit" disabled={isUpdating || email === profile?.email}>
            {isUpdating ? 'Saving...' : 'Save Changes'}
          </Button>
        </form>
      </Card>
    </div>
  );
};

const SecurityPage = () => {
  const { data: mfa, refetch: refetchMfa } = useQuery({ queryKey: ['mfa'], queryFn: () => api.get('/mfa').then(res => res.data.data) });
  const { data: passkeys, refetch: refetchPasskeys } = useQuery({ queryKey: ['passkeys'], queryFn: () => api.get('/passkeys').then(res => res.data.data) });

  const [currentPassword, setCurrentPassword] = React.useState('');
  const [newPassword, setNewPassword] = React.useState('');
  const [isChangingPass, setIsChangingPass] = React.useState(false);

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsChangingPass(true);
    try {
      await api.post('/password', { current_password: currentPassword, new_password: newPassword });
      setCurrentPassword('');
      setNewPassword('');
      alert('Password updated successfully');
    } catch (err: any) {
      alert(err.response?.data?.error?.message || 'Failed to update password');
    } finally {
      setIsChangingPass(false);
    }
  };

  const handleDeletePasskey = async (id: string) => {
    if (!confirm('Are you sure you want to delete this passkey?')) return;
    try {
      await api.delete(`/passkeys/${id}`);
      refetchPasskeys();
    } catch (err) {
      alert('Failed to delete passkey');
    }
  };

  const handleDisableMfa = async () => {
    if (!confirm('Are you sure you want to disable 2FA? This will make your account less secure.')) return;
    try {
      await api.delete('/mfa/totp');
      refetchMfa();
    } catch (err) {
      alert('Failed to disable 2FA');
    }
  };

  return (
    <div className="space-y-6 max-w-2xl">
      <Card title="Password" description="Change your password to keep your account secure.">
        <form onSubmit={handleChangePassword} className="space-y-4">
          <div className="space-y-2">
            <label>Current Password</label>
            <input
              type="password"
              value={currentPassword}
              onChange={e => setCurrentPassword(e.target.value)}
            />
          </div>
          <div className="space-y-2">
            <label>New Password</label>
            <input
              type="password"
              value={newPassword}
              onChange={e => setNewPassword(e.target.value)}
            />
          </div>
          <Button type="submit" disabled={isChangingPass || !currentPassword || !newPassword}>
            Update Password
          </Button>
        </form>
      </Card>

      <Card title="Two-Factor Authentication" description="Add an extra layer of security to your account.">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className={cn("p-2 rounded-full", mfa?.totp_enabled ? "bg-green-100 text-green-700" : "bg-zinc-100 text-zinc-400")}>
              <Shield size={20} />
            </div>
            <div>
              <p className="font-medium">Authenticator App (TOTP)</p>
              <p className="text-sm ">
                {mfa?.totp_enabled ? "Protecting your account" : "Not configured"}
              </p>
            </div>
          </div>
          {mfa?.totp_enabled ? (
            <Button variant="danger" onClick={handleDisableMfa} className="text-sm">Disable</Button>
          ) : (
            <span className="text-sm text-zinc-400">Enable in setup wizard</span>
          )}
        </div>
      </Card>

      <Card title="Passkeys" description="Use biometrics or security keys for faster, more secure login.">
        <div className="space-y-4">
          {passkeys && passkeys.length > 0 ? (
            <div className="divide-y divide-zinc-100">
              {passkeys.map((pk: any) => (
                <div key={pk.id} className="py-3 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <Key size={18} className="text-zinc-400" />
                    <div>
                      <p className="text-sm font-medium">{pk.name || 'Unnamed Passkey'}</p>
                      <p className="text-xs ">Added {new Date(pk.created_at).toLocaleDateString()}</p>
                    </div>
                  </div>
                  <Button onClick={() => handleDeletePasskey(pk.id)} className="text-xs px-2 py-1">Remove</Button>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm  py-2">No passkeys registered yet.</p>
          )}
          <Button onClick={() => alert('Registration ceremony would start here')}>
            Add a Passkey
          </Button>
        </div>
      </Card>
    </div>
  );
};

const SessionsPage = () => {
  const { data: sessions, refetch } = useQuery({ queryKey: ['sessions'], queryFn: () => api.get('/sessions').then(res => res.data.data) });

  const handleRevoke = async (id: string) => {
    try {
      await api.delete(`/sessions/${id}`);
      refetch();
    } catch (err) {
      alert('Failed to revoke session');
    }
  };

  return (
    <div className="space-y-6">
      <Card title="Active Sessions" description="Devices where you are currently logged in.">
        <div className="divide-y divide-zinc-100">
          {sessions?.map((s: any) => (
            <div key={s.id} className="py-4 flex items-center justify-between">
              <div className="flex items-center gap-4">
                <div className="p-2 bg-zinc-100 rounded-sm ">
                  <History size={20} />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <p className="font-medium text-sm">{s.ip_address}</p>
                    {s.is_current && <span className="text-[10px] bg-zinc-900 text-white px-1.5 py-0.5 rounded-full uppercase tracking-wider font-bold">Current</span>}
                  </div>
                  <p className="text-xs  truncate max-w-md">{s.user_agent}</p>
                  <p className="text-[10px] text-zinc-400 mt-1 uppercase font-semibold">Active {new Date(s.last_activity_at).toLocaleString()}</p>
                </div>
              </div>
              {!s.is_current && (
                <Button onClick={() => handleRevoke(s.id)} className="text-xs px-3 py-1.5">Log out</Button>
              )}
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
};

const Layout = () => {
  const { user, signoutRedirect, isLoading, signinRedirect } = useAuth();
  const location = useLocation();
  const [mobileMenuOpen, setMobileMenuOpen] = React.useState(false);

  useEffect(() => {
    if (!isLoading && !user) {
      signinRedirect();
    }
  }, [user, isLoading, signinRedirect]);

  if (isLoading || !user) {
    return (
      <div className="min-h-dvh flex items-center justify-center bg-zinc-50">
        <div className="flex flex-col items-center gap-4">
          <div className="w-8 h-8 border-4 border-zinc-200 border-t-zinc-900 rounded-full animate-spin" />
          <p className=" font-medium">Loading your account...</p>
        </div>
      </div>
    );
  }

  const navItems = [
    { to: '/', icon: Shield, label: 'Overview' },
    { to: '/profile', icon: User, label: 'Profile' },
    { to: '/security', icon: Key, label: 'Security' },
    { to: '/sessions', icon: History, label: 'Sessions' },
  ];

  return (
    <div className="min-h-dvh flex flex-col md:flex-row">
      {/* Sidebar */}
      <aside className={cn(
        "fixed inset-0 z-50 md:relative md:z-0 w-64 bg-white border-r border-gray-300 transform transition-transform duration-200 ease-in-out md:translate-x-0",
        mobileMenuOpen ? "translate-x-0" : "-translate-x-full"
      )}>
        <div className="flex flex-col h-full">
          <div className="p-6 flex items-center justify-between">
            <span className="text-xl font-bold tracking-tight">Autentico</span>
            <button className="md:hidden " onClick={() => setMobileMenuOpen(false)}>
              <X size={24} />
            </button>
          </div>

          <nav className="flex-1 px-4 space-y-1">
            {navItems.map(item => (
              <SidebarItem
                key={item.to}
                to={item.to}
                icon={item.icon}
                label={item.label}
                active={location.pathname === item.to}
              />
            ))}
          </nav>

          <div className="p-4 border-t border-gray-300">
            <div className="px-3 py-3 flex items-center gap-3 mb-2">
              <div className="w-8 h-8 rounded-full bg-zinc-900 flex items-center justify-center text-white text-xs font-bold">
                {user.profile.preferred_username?.[0]?.toUpperCase() || 'U'}
              </div>
              <div className="truncate">
                <p className="text-sm font-semibold truncate">{user.profile.preferred_username}</p>
                <p className="text-[10px] text-zinc-400 uppercase font-bold tracking-wider">Account</p>
              </div>
            </div>
            <button
              onClick={() => signoutRedirect()}
              className="w-full flex items-center gap-3 px-3 py-2 text-red-600 hover:bg-red-50 rounded-sm transition-colors text-sm font-medium"
            >
              <LogOut size={18} />
              Log out
            </button>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col min-w-0">
        <header className="h-16 border-b border-gray-300 bg-white flex items-center justify-between px-6 md:px-8">
          <div className="flex items-center gap-4">
            <button className="md:hidden " onClick={() => setMobileMenuOpen(true)}>
              <Menu size={24} />
            </button>
            <h1 className="text-lg font-semibold">
              {navItems.find(n => n.to === location.pathname)?.label || 'Account'}
            </h1>
          </div>
        </header>

        <div className="p-6 md:p-8 max-w-5xl">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/profile" element={<ProfilePage />} />
            <Route path="/security" element={<SecurityPage />} />
            <Route path="/sessions" element={<SessionsPage />} />
          </Routes>
        </div>
      </main>
    </div>
  );
};

const Callback = () => {
  const { signinCallback, isLoading } = useAuth();
  const navigate = useNavigate();
  const called = React.useRef(false);

  useEffect(() => {
    if (isLoading || called.current) return;
    called.current = true;
    signinCallback().then(() => {
      navigate('/');
    }).catch(err => {
      console.error(err);
      navigate('/');
    });
  }, [signinCallback, navigate, isLoading]);

  return (
    <div className="min-h-dvh flex items-center justify-center bg-zinc-50">
      <div className="w-8 h-8 border-4 border-zinc-200 border-t-zinc-900 rounded-full animate-spin" />
    </div>
  );
};

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <BrowserRouter basename="/account">
          <Routes>
            <Route path="/callback" element={<Callback />} />
            <Route path="/*" element={<Layout />} />
          </Routes>
        </BrowserRouter>
      </AuthProvider>
    </QueryClientProvider>
  );
}

export default App;
