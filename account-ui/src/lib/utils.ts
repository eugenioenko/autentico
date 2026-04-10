import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function extractError(err: unknown, fallback: string): string {
  const res = (err as { response?: { data?: { error_description?: string } } })?.response;
  return res?.data?.error_description || fallback;
}
