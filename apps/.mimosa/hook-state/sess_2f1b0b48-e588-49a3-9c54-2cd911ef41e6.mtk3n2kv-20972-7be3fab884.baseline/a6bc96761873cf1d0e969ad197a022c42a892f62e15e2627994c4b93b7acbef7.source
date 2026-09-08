import { invoke as tauriInvoke } from '@tauri-apps/api/core'

export type Locale = 'en' | 'ru'

export interface LocaleSnapshot {
  readonly locale: Locale
}

type Invoke = (command: string, args?: Record<string, unknown>) => Promise<unknown>

const locales: readonly Locale[] = ['en', 'ru']

export function isLocale(value: unknown): value is Locale {
  return typeof value === 'string' && locales.includes(value as Locale)
}

export async function loadLocale(invoke: Invoke = tauriInvoke): Promise<LocaleSnapshot> {
  const value = await invoke('get_locale')
  if (!isRecord(value) || !isLocale(value.locale)) {
    throw new Error('Invalid locale response')
  }
  return { locale: value.locale }
}

export async function saveLocale(locale: Locale, invoke: Invoke = tauriInvoke): Promise<LocaleSnapshot> {
  if (!isLocale(locale)) throw new Error('Invalid locale')
  const value = await invoke('set_locale', { locale })
  if (!isRecord(value) || !isLocale(value.locale) || value.locale !== locale) {
    throw new Error('Invalid locale acknowledgement')
  }
  return { locale: value.locale }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}
