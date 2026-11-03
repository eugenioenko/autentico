import { useSyncExternalStore } from "react";

export type Scheme = "light" | "dark";
export type ThemeChoice = Scheme | "system";

const STORAGE_KEY = "autentico-admin-theme";
const darkQuery = () => window.matchMedia("(prefers-color-scheme: dark)");
const listeners = new Set<() => void>();
let memoryChoice: ThemeChoice = "system";

function readChoice(): ThemeChoice {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    return stored === "light" || stored === "dark" ? stored : "system";
  } catch {
    return memoryChoice;
  }
}

function apply(choice: ThemeChoice) {
  const root = document.documentElement;
  root.style.colorScheme = choice === "system" ? "" : choice;
  root.dataset.theme = choice;
}

export function applyStoredTheme() {
  apply(readChoice());
}

function store(choice: ThemeChoice) {
  memoryChoice = choice;
  try {
    if (choice === "system") localStorage.removeItem(STORAGE_KEY);
    else localStorage.setItem(STORAGE_KEY, choice);
  } catch {
    return;
  }
}

export function setTheme(choice: ThemeChoice) {
  store(choice);
  apply(choice);
  listeners.forEach((l) => l());
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  const query = darkQuery();
  query.addEventListener("change", listener);
  return () => {
    listeners.delete(listener);
    query.removeEventListener("change", listener);
  };
}

export function useThemeChoice(): ThemeChoice {
  return useSyncExternalStore(subscribe, readChoice);
}

export function useColorScheme(): Scheme {
  return useSyncExternalStore(subscribe, () => {
    const choice = readChoice();
    if (choice !== "system") return choice;
    return darkQuery().matches ? "dark" : "light";
  });
}
