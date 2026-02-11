import axios from "axios";
import { UserManager } from "oidc-client-ts";

const apiClient = axios.create();

// Lazy reference to UserManager — set by AuthProvider
let _userManager: UserManager | null = null;

export function setUserManager(mgr: UserManager) {
  _userManager = mgr;
}

apiClient.interceptors.request.use(async (config) => {
  if (_userManager) {
    const user = await _userManager.getUser();
    if (user?.access_token) {
      config.headers.Authorization = `Bearer ${user.access_token}`;
    }
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
      !_userManager
    ) {
      return Promise.reject(error);
    }

    originalRequest._retry = true;

    try {
      const user = await _userManager.signinSilent();
      if (user?.access_token) {
        originalRequest.headers.Authorization = `Bearer ${user.access_token}`;
        return apiClient(originalRequest);
      }
    } catch {
      // Silent renew failed
    }

    await _userManager.removeUser();
    window.location.href = "/admin/login";
    return Promise.reject(error);
  }
);

export default apiClient;
