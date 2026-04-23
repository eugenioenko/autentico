export function describeUserAgent(ua: string): string {
  if (!ua) return "Unknown device";
  let browser = "Browser";
  if (/edg\//i.test(ua)) browser = "Edge";
  else if (/chrome\//i.test(ua) && !/chromium/i.test(ua)) browser = "Chrome";
  else if (/firefox\//i.test(ua)) browser = "Firefox";
  else if (/safari\//i.test(ua) && !/chrome/i.test(ua)) browser = "Safari";
  else if (/opr\//i.test(ua) || /opera/i.test(ua)) browser = "Opera";
  let os = "Unknown OS";
  if (/windows nt/i.test(ua)) os = "Windows";
  else if (/mac os x/i.test(ua)) os = "macOS";
  else if (/android/i.test(ua)) os = "Android";
  else if (/iphone|ipad|ipod/i.test(ua)) os = "iOS";
  else if (/linux/i.test(ua)) os = "Linux";
  return `${browser} on ${os}`;
}

export function formatActiveAppsCount(n: number): string {
  if (n === 0) return "No apps signed in";
  if (n === 1) return "1 app signed in";
  return `${n} apps signed in`;
}
