import { beforeEach, describe, expect, it, vi } from 'vitest'

import {
  applyOwnerLocale,
  captureLocaleRead,
  commitLocale,
  currentLocale,
  isLocaleAcknowledgement,
  localeWritePending,
} from './locale'

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>(resolvePromise => { resolve = resolvePromise })
  return { promise, resolve }
}

describe('locale owner ordering', () => {
  beforeEach(async () => {
    await vi.waitFor(() => expect(localeWritePending.value).toBe(false))
    currentLocale.value = 'en'
  })

  it('rejects acknowledgement extras outside the sole locale field', () => {
    const symbolExtra = { locale: 'ru' as const, [Symbol('extra')]: true }
    const nonEnumerableExtra = { locale: 'ru' as const }
    Object.defineProperty(nonEnumerableExtra, 'extra', { value: true })

    expect(isLocaleAcknowledgement({ locale: 'ru' })).toBe(true)
    expect(isLocaleAcknowledgement(symbolExtra)).toBe(false)
    expect(isLocaleAcknowledgement(nonEnumerableExtra)).toBe(false)
  })

  it.each([
    ['mismatched', async () => ({ locale: 'en' as const })],
    ['malformed', async () => undefined],
    ['rejected', async () => { throw new Error('rejected') }],
  ])('preserves the committed locale after a %s acknowledgement', async (_case, save) => {
    await expect(commitLocale('ru', save)).rejects.toThrow()
    expect(currentLocale.value).toBe('en')
  })

  it('rejects an owner read captured before a later write', async () => {
    const readOrder = captureLocaleRead()
    const acknowledgement = deferred<{ locale: 'ru' }>()
    const write = commitLocale('ru', async () => acknowledgement.promise)

    acknowledgement.resolve({ locale: 'ru' })
    await write

    expect(applyOwnerLocale('en', readOrder)).toBe(false)
    expect(currentLocale.value).toBe('ru')
  })

  it('rejects an owner read captured while a write is pending', async () => {
    const acknowledgement = deferred<{ locale: 'ru' }>()
    const write = commitLocale('ru', async () => acknowledgement.promise)
    const readOrder = captureLocaleRead()

    acknowledgement.resolve({ locale: 'ru' })
    await write

    expect(readOrder).toBeNull()
    expect(applyOwnerLocale('en', readOrder)).toBe(false)
    expect(currentLocale.value).toBe('ru')
  })
})
