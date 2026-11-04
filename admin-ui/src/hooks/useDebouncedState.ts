import { useCallback, useEffect, useRef, useState } from "react";

/** Delays state updates; immediate updates also cancel any pending change. */
export function useDebouncedState<T>(initial: T, timeInMs = 350) {
  const [value, setValue] = useState(initial);
  const timeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const setDebouncedValue = useCallback((next: T, immediate = false) => {
    if (timeoutRef.current !== null) clearTimeout(timeoutRef.current);
    timeoutRef.current = null;
    if (immediate) {
      setValue(() => next);
    } else {
      timeoutRef.current = setTimeout(() => {
        timeoutRef.current = null;
        setValue(() => next);
      }, timeInMs);
    }
  }, [timeInMs]);

  useEffect(() => () => {
    if (timeoutRef.current !== null) clearTimeout(timeoutRef.current);
  }, []);

  return [value, setDebouncedValue] as const;
}
