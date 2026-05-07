import axios from "axios";

const apiClient = axios.create();

let _getToken: (() => string | null) | null = null;
let _login: (() => void) | null = null;
let _refresh: (() => Promise<void>) | null = null;

export function setAuth(getToken: () => string | null, login: () => void, refresh: () => Promise<void>) {
  _getToken = getToken;
  _login = login;
  _refresh = refresh;
}

apiClient.interceptors.request.use((config) => {
  const token = _getToken?.();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    if (error.response?.status !== 401 || originalRequest._retry) {
      return Promise.reject(error);
    }

    originalRequest._retry = true;

    if (_refresh) {
      try {
        await _refresh();
        const token = _getToken?.();
        if (token) {
          originalRequest.headers.Authorization = `Bearer ${token}`;
          return apiClient(originalRequest);
        }
      } catch {
        // refresh failed — fall through to login
      }
    }

    _login?.();
    return Promise.reject(error);
  }
);

export default apiClient;
