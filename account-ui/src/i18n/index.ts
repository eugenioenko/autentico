import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import en from "./locales/en.json";
import zh from "./locales/zh.json";

const STORAGE_KEY = "autentico-account-lang";

function getInitialLang(): string {
  // First check localStorage for saved preference
  const saved = localStorage.getItem(STORAGE_KEY);
  if (saved === "en" || saved === "zh") return saved;

  // Detect browser language, fallback to en
  const browserLang = navigator.language || navigator.languages?.[0] || "";
  if (browserLang.startsWith("zh")) {
    return "zh";
  }

  // Default to English
  return "en";
}

i18n.use(initReactI18next).init({
  resources: {
    en: { translation: en },
    zh: { translation: zh },
  },
  lng: getInitialLang(),
  fallbackLng: "en",
  interpolation: {
    escapeValue: false,
  },
});

export function changeLanguage(lang: string) {
  localStorage.setItem(STORAGE_KEY, lang);
  i18n.changeLanguage(lang);
}

export function getCurrentLanguage(): string {
  return i18n.language;
}

export default i18n;
