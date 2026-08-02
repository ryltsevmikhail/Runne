import { localeCodes, type Locale } from "./types";

export const defaultLocale: Locale = "en";
export const localeStorageKey = "gocode.locale";

export const localeMetadata: Record<
  Locale,
  { nativeName: string; htmlLang: string; ogLocale: string }
> = {
  en: { nativeName: "English", htmlLang: "en", ogLocale: "en_US" },
  ru: { nativeName: "Русский", htmlLang: "ru", ogLocale: "ru_RU" },
  "zh-cn": { nativeName: "简体中文", htmlLang: "zh-CN", ogLocale: "zh_CN" },
  "pt-br": {
    nativeName: "Português (Brasil)",
    htmlLang: "pt-BR",
    ogLocale: "pt_BR",
  },
  es: { nativeName: "Español", htmlLang: "es", ogLocale: "es_ES" },
  de: { nativeName: "Deutsch", htmlLang: "de", ogLocale: "de_DE" },
  ja: { nativeName: "日本語", htmlLang: "ja", ogLocale: "ja_JP" },
  ko: { nativeName: "한국어", htmlLang: "ko", ogLocale: "ko_KR" },
  fr: { nativeName: "Français", htmlLang: "fr", ogLocale: "fr_FR" },
};

export function isLocale(value: unknown): value is Locale {
  return typeof value === "string" && localeCodes.includes(value as Locale);
}

export function localeFromLanguage(value: string): Locale | undefined {
  const normalized = value.trim().toLowerCase().replaceAll("_", "-");
  if (isLocale(normalized)) return normalized;
  if (normalized.startsWith("zh")) return "zh-cn";
  if (normalized.startsWith("pt")) return "pt-br";
  return localeCodes.find((locale) => normalized.startsWith(`${locale}-`));
}

export function resolveLocale(
  stored: string | null | undefined,
  browserLanguages: readonly string[],
): Locale {
  if (isLocale(stored)) return stored;
  for (const language of browserLanguages) {
    const locale = localeFromLanguage(language);
    if (locale) return locale;
  }
  return defaultLocale;
}

export interface LocaleStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

export function readStoredLocale(storage?: LocaleStorage): string | null {
  try {
    return storage?.getItem(localeStorageKey) ?? null;
  } catch {
    return null;
  }
}

export function persistLocale(storage: LocaleStorage | undefined, locale: Locale) {
  try {
    storage?.setItem(localeStorageKey, locale);
  } catch {
    // A blocked storage backend must not prevent language switching in memory.
  }
}
