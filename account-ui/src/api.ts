import axios from 'axios';
import type { AuthTokens } from 'oidc-js-react';

declare module 'axios' {
  interface InternalAxiosRequestConfig {
    _retryCount?: number;
  }
}

const MAX_RETRIES = 3;

let _getToken: (() => string | null) | null = null;
let _login: (() => void) | null = null;
let _refresh: (() => Promise<AuthTokens>) | null = null;

export function setAuth(getToken: () => string | null, login: () => void, refresh: () => Promise<AuthTokens>) {
  _getToken = getToken;
  _login = login;
  _refresh = refresh;
}

const api = axios.create({
  baseURL: '/account/api',
});

api.interceptors.request.use((config) => {
  if (config._retryCount) return config;
  const token = _getToken?.();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    const retryCount = originalRequest._retryCount ?? 0;

    if (error?.response?.status !== 401 || retryCount >= MAX_RETRIES) {
      return Promise.reject(error);
    }

    originalRequest._retryCount = retryCount + 1;

    if (_refresh) {
      try {
        const tokens = await _refresh();
        if (tokens.access) {
          originalRequest.headers.Authorization = `Bearer ${tokens.access}`;
          return api(originalRequest);
        }
      } catch {
        // refresh failed — fall through to login
      }
    }

    _login?.();
    return Promise.reject(error);
  },
);

export default api;
