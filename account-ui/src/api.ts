import axios from 'axios';
import type { UserManager } from 'oidc-client-ts';

let _userManager: UserManager | null = null;
let _reauthInFlight = false;

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

// A 401 from the account API means the access token was revoked or the
// underlying IdP session was cascaded (e.g. another device revoked this one).
// Drop the stored user and route back through /oauth2/authorize — either the
// browser still has a valid IdP cookie and auto-logs-in, or it lands on the
// login page. The `_reauthInFlight` guard prevents concurrent 401s from
// triggering multiple redirects before the browser has navigated away.
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error?.response?.status === 401 && _userManager && !_reauthInFlight) {
      _reauthInFlight = true;
      try {
        await _userManager.removeUser();
      } catch {
        /* ignore */
      }
      try {
        await _userManager.signinRedirect();
      } catch {
        window.location.assign('/account/');
      }
    }
    return Promise.reject(error);
  },
);

export default api;
