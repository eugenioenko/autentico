import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider } from './AuthContext';
import { SettingsProvider } from './context/SettingsContext';
import Layout from './components/Layout';
import Callback from './pages/Callback';

const queryClient = new QueryClient();

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <SettingsProvider>
        <AuthProvider>
          <BrowserRouter basename="/account">
            <Routes>
              <Route path="/callback" element={<Callback />} />
              <Route path="/*" element={<Layout />} />
            </Routes>
          </BrowserRouter>
        </AuthProvider>
      </SettingsProvider>
    </QueryClientProvider>
  );
}

export default App;
