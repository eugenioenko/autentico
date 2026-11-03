import { useLayoutEffect, useRef, useState, type DependencyList, type RefObject } from "react";

const MIN_HEIGHT = 240;

function scrollParent(element: HTMLElement): HTMLElement {
  for (let node = element.parentElement; node; node = node.parentElement) {
    const { overflowY } = getComputedStyle(node);
    if (overflowY === "auto" || overflowY === "scroll") return node;
  }
  return document.documentElement;
}

export function useFillHeight(target: RefObject<HTMLElement | null>, below: RefObject<HTMLElement | null>, deps: DependencyList) {
  const [height, setHeight] = useState<number>();
  const measureRef = useRef<() => void>(() => {});

  measureRef.current = () => {
    const element = target.current;
    if (!element) return;
    const scroller = scrollParent(element);
    const offset = element.getBoundingClientRect().top - scroller.getBoundingClientRect().top + scroller.scrollTop;
    const padding = parseFloat(getComputedStyle(scroller).paddingBottom) || 0;
    const footer = below.current;
    const footerSpace = footer ? footer.getBoundingClientRect().bottom - element.getBoundingClientRect().bottom : 0;
    const next = Math.max(MIN_HEIGHT, Math.floor(scroller.clientHeight - offset - padding - footerSpace));
    setHeight((current) => (current !== undefined && Math.abs(current - next) < 2 ? current : next));
  };

  useLayoutEffect(() => measureRef.current(), deps);

  useLayoutEffect(() => {
    const element = target.current;
    if (!element) return;
    const measure = () => measureRef.current();
    const observer = new ResizeObserver(measure);
    observer.observe(scrollParent(element));
    window.addEventListener("resize", measure);
    return () => {
      observer.disconnect();
      window.removeEventListener("resize", measure);
    };
  }, [target]);

  return height;
}
