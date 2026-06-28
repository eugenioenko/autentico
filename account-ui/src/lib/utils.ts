import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function extractError(err: unknown, fallback: string): string {
  const res = (err as { response?: { data?: { error_description?: string } } })?.response;
  return res?.data?.error_description || fallback;
}

// Tiny heuristic: turn a raw User-Agent string into "Browser on OS".
// Not a full UA parser — a bundle-friendly best effort.
export function describeUserAgent(ua: string): string {
  if (!ua) return '未知设备';
  let browser = '浏览器';
  if (/edg\//i.test(ua)) browser = 'Edge';
  else if (/chrome\//i.test(ua) && !/chromium/i.test(ua)) browser = 'Chrome';
  else if (/firefox\//i.test(ua)) browser = 'Firefox';
  else if (/safari\//i.test(ua) && !/chrome/i.test(ua)) browser = 'Safari';
  else if (/opr\//i.test(ua) || /opera/i.test(ua)) browser = 'Opera';
  let os = '未知操作系统';
  if (/windows nt/i.test(ua)) os = 'Windows';
  else if (/mac os x/i.test(ua)) os = 'macOS';
  else if (/android/i.test(ua)) os = 'Android';
  else if (/iphone|ipad|ipod/i.test(ua)) os = 'iOS';
  else if (/linux/i.test(ua)) os = 'Linux';
  return `${browser} on ${os}`;
}

export function formatActiveAppsCount(n: number): string {
  if (n === 0) return '无已登录应用';
  if (n === 1) return '1 个已登录应用';
  return `${n} 个已登录应用`;
}
