import axios from "axios";

const apiClient = axios.create();

let _getToken: (() => string | null) | null = null;
let _login: (() => void) | null = null;

export function setAuth(getToken: () => string | null, login: () => void) {
  _getToken = getToken;
  _login = login;
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

    if (
      error.response?.status !== 401 ||
      originalRequest._retry ||
      !_login
    ) {
      return Promise.reject(error);
    }

    originalRequest._retry = true;
    _login();
    return Promise.reject(error);
  }
);

export default apiClient;
