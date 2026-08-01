import { computed, readonly, ref } from "vue";
import { getDictionary } from ".";
import {
  persistLocale,
  readStoredLocale,
  resolveLocale,
} from "./locales";
import type { Locale } from "./types";

function browserStorage(): Storage | undefined {
  try {
    return typeof window === "undefined" ? undefined : window.localStorage;
  } catch {
    return undefined;
  }
}

function browserLocale(): Locale {
  if (typeof window === "undefined") return "en";
  return resolveLocale(
    readStoredLocale(browserStorage()),
    navigator.languages.length > 0 ? navigator.languages : [navigator.language],
  );
}

const activeLocale = ref<Locale>("en");
const dictionary = computed(() => getDictionary(activeLocale.value));

export function initializeBrowserLocale() {
  activeLocale.value = browserLocale();
}

export function useSiteI18n() {
  function setLocale(locale: Locale) {
    activeLocale.value = locale;
    persistLocale(browserStorage(), locale);
  }

  return {
    locale: readonly(activeLocale),
    dictionary,
    setLocale,
  };
}
