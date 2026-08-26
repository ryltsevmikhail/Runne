import { beforeEach, describe, expect, it, vi } from 'vitest'

const nativeLocale = vi.hoisted(() => ({
  isTauri: vi.fn(),
  loadLocale: vi.fn(),
}))

vi.mock('@tauri-apps/api/core', () => ({ isTauri: nativeLocale.isTauri }))
vi.mock('@/shared/api/platform/locale', async (importOriginal) => ({
  ...await importOriginal<typeof import('@/shared/api/platform/locale')>(),
  loadLocale: nativeLocale.loadLocale,
}))

import { commitLocale, currentLocale, localeWritePending } from '@/shared/model/locale'

import { createTranslator, loadOwnedLocale, localeCatalogs, validateLocaleCatalogs } from './index'

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>(resolvePromise => { resolve = resolvePromise })
  return { promise, resolve }
}

describe('desktop locale catalogs', () => {
  beforeEach(async () => {
    await vi.waitFor(() => expect(localeWritePending.value).toBe(false))
    currentLocale.value = 'en'
    nativeLocale.isTauri.mockReturnValue(true)
    nativeLocale.loadLocale.mockReset()
  })

  it('has matching production keys in Russian and English', () => {
    expect(validateLocaleCatalogs(localeCatalogs)).toEqual([])
  })

  it('formats stable messages without concatenating sentences', () => {
    expect(createTranslator('ru')('settings.loading', { page: 'настроек' })).toBe('Загрузка настроек')
    expect(createTranslator('en')('settings.retry')).toBe('Retry')
  })

  it('does not apply a delayed production read captured before a newer acknowledgement', async () => {
    const read = deferred<{ locale: 'en' }>()
    nativeLocale.loadLocale.mockReturnValue(read.promise)
    const staleRead = loadOwnedLocale()

    const acknowledgement = deferred<{ locale: 'ru' }>()
    const write = commitLocale('ru', async () => acknowledgement.promise)
    acknowledgement.resolve({ locale: 'ru' })
    await write

    read.resolve({ locale: 'en' })
    await expect(staleRead).resolves.toBe('ru')
    expect(currentLocale.value).toBe('ru')
  })

  it('does not apply a production read captured while an acknowledgement is pending', async () => {
    const acknowledgement = deferred<{ locale: 'ru' }>()
    const write = commitLocale('ru', async () => acknowledgement.promise)
    const read = deferred<{ locale: 'en' }>()
    nativeLocale.loadLocale.mockReturnValue(read.promise)
    const staleRead = loadOwnedLocale()

    acknowledgement.resolve({ locale: 'ru' })
    await write
    read.resolve({ locale: 'en' })

    await expect(staleRead).resolves.toBe('ru')
    expect(currentLocale.value).toBe('ru')
  })

  it('does not apply a delayed read after a concurrent rejected write', async () => {
    const read = deferred<{ locale: 'ru' }>()
    nativeLocale.loadLocale.mockReturnValue(read.promise)
    const staleRead = loadOwnedLocale()

    await expect(commitLocale('ru', async () => { throw new Error('rejected') })).rejects.toThrow('rejected')
    read.resolve({ locale: 'ru' })

    await expect(staleRead).resolves.toBe('en')
    expect(currentLocale.value).toBe('en')
  })
})
