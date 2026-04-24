import { useState, useEffect, useCallback, type RefObject } from "react";

export function useTableScrollY(containerRef: RefObject<HTMLDivElement | null>) {
  const [scrollY, setScrollY] = useState<number | undefined>(undefined);

  const measure = useCallback(() => {
    const el = containerRef.current;
    if (!el) return;
    const table = el.querySelector(".ant-table-wrapper");
    if (!table) return;

    const header = el.querySelector<HTMLElement>(".ant-table-header");
    const pagination = el.querySelector<HTMLElement>(".ant-table-pagination");

    const containerHeight = el.clientHeight;
    const headerHeight = header?.offsetHeight ?? 39;
    const paginationHeight = pagination
      ? pagination.offsetHeight + parseFloat(getComputedStyle(pagination).marginTop || "0")
      : 56;

    const y = containerHeight - headerHeight - paginationHeight;
    if (y > 0) setScrollY(y);
  }, [containerRef]);

  useEffect(() => {
    measure();
    const obs = new ResizeObserver(measure);
    if (containerRef.current) obs.observe(containerRef.current);
    return () => obs.disconnect();
  }, [containerRef, measure]);

  return scrollY;
}
