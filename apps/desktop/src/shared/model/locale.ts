import { ref } from 'vue'

import type { Locale } from '@/shared/api/platform/locale'

export interface LocaleAcknowledgement {
  readonly locale: Locale
}

type SaveLocale = (locale: Locale) => Promise<unknown>

/** Renderer projection of the Rust-owned persisted locale setting. */
export const currentLocale = ref<Locale>('en')
export const localeWritePending = ref(false)

let pendingLocaleWrite: Promise<LocaleAcknowledgement> | null = null
let localeWriteOrder = 0

export function captureLocaleRead(): number | null {
  return pendingLocaleWrite === null ? localeWriteOrder : null
}

export function applyOwnerLocale(locale: Locale, readOrder: number | null): boolean {
  if (readOrder === null || pendingLocaleWrite !== null || readOrder !== localeWriteOrder) return false
  currentLocale.value = locale
  return true
}

export async function commitLocale(
  locale: Locale,
  save: SaveLocale,
): Promise<LocaleAcknowledgement | null> {
  if (pendingLocaleWrite !== null) return null
  localeWriteOrder += 1
  localeWritePending.value = true
  const completion = Promise.resolve()
    .then(() => save(locale))
    .then((acknowledgement) => {
      if (!isLocaleAcknowledgement(acknowledgement) || acknowledgement.locale !== locale) {
        throw new Error('Invalid locale acknowledgement')
      }
      currentLocale.value = acknowledgement.locale
      return acknowledgement
    })
  pendingLocaleWrite = completion
  try {
    return await completion
  }
  finally {
    if (pendingLocaleWrite === completion) {
      pendingLocaleWrite = null
      localeWritePending.value = false
    }
  }
}

export function isLocaleAcknowledgement(value: unknown): value is LocaleAcknowledgement {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false
  const keys = Reflect.ownKeys(value)
  if (keys.length !== 1 || keys[0] !== 'locale' || !Object.hasOwn(value, 'locale')) return false
  const locale = (value as Record<string, unknown>).locale
  return locale === 'en' || locale === 'ru'
}
