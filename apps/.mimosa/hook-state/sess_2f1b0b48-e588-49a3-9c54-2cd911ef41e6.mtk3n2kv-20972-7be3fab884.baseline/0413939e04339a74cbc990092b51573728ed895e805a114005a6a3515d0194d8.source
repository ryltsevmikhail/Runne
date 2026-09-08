import { beforeEach, describe, expect, it, vi } from 'vitest'

import {
  appTheme,
  captureThemeRead,
  commitTheme,
  applyOwnerTheme,
  themeWritePending,
} from './theme'

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason?: unknown) => void
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, reject, resolve }
}

describe('theme write gate', () => {
  beforeEach(() => {
    appTheme.value = 'dark'
  })

  it('keeps the committed theme until the exact owner acknowledgement arrives', async () => {
    const acknowledgement = deferred<{ theme: 'light' }>()
    const commit = commitTheme('light', async () => acknowledgement.promise)

    expect(themeWritePending.value).toBe(true)
    expect(appTheme.value).toBe('dark')

    acknowledgement.resolve({ theme: 'light' })
    await expect(commit).resolves.toEqual({ theme: 'light' })
    expect(appTheme.value).toBe('light')
  })

  it('suppresses an overlapping write so reversed completions cannot win', async () => {
    const first = deferred<{ theme: 'light' }>()
    const firstSave = vi.fn().mockReturnValue(first.promise)
    const secondSave = vi.fn().mockResolvedValue({ theme: 'dark' })

    const initial = commitTheme('light', firstSave)
    await expect(commitTheme('dark', secondSave)).resolves.toBeNull()
    expect(secondSave).not.toHaveBeenCalled()

    first.resolve({ theme: 'light' })
    await expect(initial).resolves.toEqual({ theme: 'light' })
    expect(appTheme.value).toBe('light')
  })

  it('keeps the prior committed theme when the owner rejects a write', async () => {
    const acknowledgement = deferred<{ theme: 'light' }>()
    const commit = commitTheme('light', async () => acknowledgement.promise)

    acknowledgement.reject(new Error('owner rejected'))
    await expect(commit).rejects.toThrow('owner rejected')
    expect(appTheme.value).toBe('dark')
    expect(themeWritePending.value).toBe(false)
  })

  it('rejects an owner snapshot that began before a later write', async () => {
    const staleRead = captureThemeRead()
    const acknowledgement = deferred<{ theme: 'light' }>()
    const commit = commitTheme('light', async () => acknowledgement.promise)

    expect(applyOwnerTheme('dark', staleRead)).toBe(false)
    acknowledgement.resolve({ theme: 'light' })
    await commit
    expect(appTheme.value).toBe('light')
  })

  it('rejects an owner snapshot captured while a write is pending after its acknowledgement', async () => {
    const acknowledgement = deferred<{ theme: 'light' }>()
    const commit = commitTheme('light', async () => acknowledgement.promise)
    const staleRead = captureThemeRead()

    acknowledgement.resolve({ theme: 'light' })
    await commit
    expect(applyOwnerTheme('dark', staleRead)).toBe(false)
    expect(appTheme.value).toBe('light')
  })
})
