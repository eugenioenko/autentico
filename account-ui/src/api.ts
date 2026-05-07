import axios from 'axios';

let _getToken: (() => string | null) | null = null;
let _login: (() => void) | null = null;
let _reauthInFlight = false;

export function setAuth(getToken: () => string | null, login: () => void) {
  _getToken = getToken;
  _login = login;
}

const api = axios.create({
  baseURL: '/account/api',
});

api.interceptors.request.use((config) => {
  const token = _getToken?.();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error?.response?.status === 401 && _login && !_reauthInFlight) {
      _reauthInFlight = true;
      _login();
    }
    return Promise.reject(error);
  },
);

export default api;
