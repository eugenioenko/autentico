export const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export const URL_PATTERN = /^[a-z][a-z0-9+.-]*:\/\/\S+$/i;

export function emailRule(message = "Must be a valid email") {
  return { value: EMAIL_PATTERN, message };
}

export function urlRule(message = "Must be a valid URL") {
  return { value: URL_PATTERN, message };
}
