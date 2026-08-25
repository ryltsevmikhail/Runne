import { ref } from 'vue'
import { isTauri } from '@tauri-apps/api/core'

import { loadLocale, type Locale } from '@/shared/api/platform/locale'

import english from './english'
import russian from './russian'

export const localeCatalogs = { en: english, ru: russian } as const
export type LocaleKey = keyof typeof english
export const currentLocale = ref<Locale>('en')

export function validateLocaleCatalogs(
  catalogs: Readonly<Record<Locale, Readonly<Record<string, string>>>>,
): string[] {
  const expected = Object.keys(catalogs.en).sort()
  return (['en', 'ru'] as const).flatMap(locale => {
    const actual = Object.keys(catalogs[locale]).sort()
    return expected.filter(key => !actual.includes(key)).map(key => `${locale}:${key}`)
  })
}

const catalogErrors = validateLocaleCatalogs(localeCatalogs)
if (catalogErrors.length > 0) {
  throw new Error(`Missing production locale keys: ${catalogErrors.join(', ')}`)
}

export function createTranslator(locale: Locale) {
  return (key: LocaleKey, values: Readonly<Record<string, string | number>> = {}): string => {
    const template = localeCatalogs[locale][key]
    return template.replace(/\{([A-Za-z0-9_]+)\}/g, (match, name: string) =>
      Object.hasOwn(values, name) ? String(values[name]) : match)
  }
}

export function translate(
  key: LocaleKey,
  values?: Readonly<Record<string, string | number>>,
): string {
  return createTranslator(currentLocale.value)(key, values)
}

export async function loadOwnedLocale(): Promise<Locale> {
  if (!isTauri()) return currentLocale.value
  const snapshot = await loadLocale()
  currentLocale.value = snapshot.locale
  return snapshot.locale
}
