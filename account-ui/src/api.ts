import axios from 'axios';
import type { UserManager } from 'oidc-client-ts';

let _userManager: UserManager | null = null;

export function setUserManager(mgr: UserManager) {
  _userManager = mgr;
}

const api = axios.create({
  baseURL: '/account/api',
});

api.interceptors.request.use(async (config) => {
  if (_userManager) {
    const user = await _userManager.getUser();
    if (user?.access_token) {
      config.headers.Authorization = `Bearer ${user.access_token}`;
    }
  }
  return config;
});

export default api;
