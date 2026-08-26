import { mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { currentLocale } from '@/shared/i18n'
import { appTheme } from '@/shared/model/theme'
import { commitTheme } from '@/shared/model/theme'
import { themeWritePending } from '@/shared/model/theme'

import AppearancePage from './AppearancePage.vue'

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>(resolvePromise => {
    resolve = resolvePromise
  })
  return { promise, resolve }
}

describe('AppearancePage', () => {
  beforeEach(async () => {
    await vi.waitFor(() => expect(themeWritePending.value).toBe(false))
    appTheme.value = 'dark'
    currentLocale.value = 'en'
  })

  it('commits a theme only after its owner acknowledgement', async () => {
    const acknowledgement = deferred<{ theme: 'light' }>()
    const saveTheme = vi.fn().mockReturnValue(acknowledgement.promise)
    appTheme.value = 'dark'
    const wrapper = mount(AppearancePage, {
      props: {
        loadAppearance: async () => ({ theme: 'dark' as const }),
        saveAppearance: saveTheme,
      },
      global: { stubs: { RouterLink: true } },
    })

    await vi.waitFor(() => expect(wrapper.get('input[value="dark"]').element).toBeTruthy())
    await wrapper.get('input[value="light"]').setValue(true)
    expect(saveTheme).toHaveBeenCalledWith('light')
    expect(appTheme.value).toBe('dark')
    expect(wrapper.get('.appearance-status').text()).toContain('Dark theme enabled')

    acknowledgement.resolve({ theme: 'light' })
    await vi.waitFor(() => expect((wrapper.get('input[value="light"]').element as HTMLInputElement).checked).toBe(true))
    await vi.waitFor(() => expect(appTheme.value).toBe('light'))
    await vi.waitFor(() => expect(themeWritePending.value).toBe(false))
  })

  it('suppresses duplicate theme selections while an owner acknowledgement is pending', async () => {
    const acknowledgement = deferred<{ theme: 'light' }>()
    const saveTheme = vi.fn().mockReturnValue(acknowledgement.promise)
    const wrapper = mount(AppearancePage, {
      props: {
        loadAppearance: async () => ({ theme: 'dark' as const }),
        saveAppearance: saveTheme,
      },
      global: { stubs: { RouterLink: true } },
    })

    await vi.waitFor(() => expect(wrapper.get('input[value="light"]').element).toBeTruthy())
    await wrapper.get('input[value="light"]').setValue(true)
    await wrapper.get('input[value="dark"]').setValue(true)

    expect(saveTheme).toHaveBeenCalledTimes(1)
    expect(wrapper.get('fieldset').attributes('aria-busy')).toBe('true')
    expect(wrapper.get('fieldset').attributes('disabled')).toBeDefined()
    acknowledgement.resolve({ theme: 'light' })
    await vi.waitFor(() => expect((wrapper.get('input[value="light"]').element as HTMLInputElement).checked).toBe(true))
    await vi.waitFor(() => expect(themeWritePending.value).toBe(false))
  })

  it('keeps an acknowledged shared theme when mounted outside Tauri', async () => {
    appTheme.value = 'light'
    const wrapper = mount(AppearancePage, {
      global: { stubs: { RouterLink: true } },
    })

    await vi.waitFor(() => expect((wrapper.get('input[value="light"]').element as HTMLInputElement).checked).toBe(true))
    expect(appTheme.value).toBe('light')
  })

  it('shares the pending owner write with the toolbar consumer', async () => {
    const toolbarAcknowledgement = deferred<{ theme: 'light' }>()
    const toolbarCommit = commitTheme('light', async () => toolbarAcknowledgement.promise)
    const saveTheme = vi.fn().mockResolvedValue({ theme: 'light' })
    const wrapper = mount(AppearancePage, {
      props: {
        loadAppearance: async () => ({ theme: 'dark' as const }),
        saveAppearance: saveTheme,
      },
      global: { stubs: { RouterLink: true } },
    })

    await vi.waitFor(() => expect(wrapper.get('input[value="light"]').element).toBeTruthy())
    await wrapper.get('input[value="light"]').setValue(true)
    expect(saveTheme).not.toHaveBeenCalled()

    toolbarAcknowledgement.resolve({ theme: 'light' })
    await toolbarCommit
    await vi.waitFor(() => expect((wrapper.get('input[value="light"]').element as HTMLInputElement).checked).toBe(true))
    await vi.waitFor(() => expect(themeWritePending.value).toBe(false))
  })

  it('rolls back and reports a failed save', async () => {
    const wrapper = mount(AppearancePage, {
      props: {
        loadAppearance: async () => ({ theme: 'dark' as const }),
        saveAppearance: async () => { throw new Error('rejected') },
      },
      global: { stubs: { RouterLink: true } },
    })

    await vi.waitFor(() => expect(wrapper.get('input[value="dark"]').element).toBeTruthy())
    await wrapper.get('input[value="light"]').setValue(true)
    await vi.waitFor(() => expect(wrapper.get('[role="alert"]').text()).toContain('could not be saved'))
    expect(appTheme.value).toBe('dark')
  })

  it('keeps the committed locale until its owner acknowledgement arrives', async () => {
    const acknowledgement = deferred<{ locale: 'ru' }>()
    const saveLocale = vi.fn().mockReturnValue(acknowledgement.promise)
    const wrapper = mount(AppearancePage, {
      props: {
        loadAppearance: async () => ({ theme: 'dark' as const }),
        loadLocale: async () => ({ locale: 'en' as const }),
        saveLocale: saveLocale as never,
      },
      global: { stubs: { RouterLink: true } },
    })

    await vi.waitFor(() => expect(wrapper.get('select[name="locale"]').element).toBeTruthy())
    await wrapper.get('select[name="locale"]').setValue('ru')
    expect(saveLocale).toHaveBeenCalledWith('ru')
    expect(currentLocale.value).toBe('en')
    expect((wrapper.get('select[name="locale"]').element as HTMLSelectElement).value).toBe('en')
    expect(wrapper.get('fieldset.appearance-locale').attributes('aria-busy')).toBe('true')
    expect(wrapper.get('fieldset.appearance-locale').attributes('disabled')).toBeDefined()

    acknowledgement.resolve({ locale: 'ru' })
    await vi.waitFor(() => expect(currentLocale.value).toBe('ru'))
  })

  it('suppresses duplicate locale selections while the owner acknowledgement is pending', async () => {
    const acknowledgement = deferred<{ locale: 'ru' }>()
    const saveLocale = vi.fn().mockReturnValue(acknowledgement.promise)
    const wrapper = mount(AppearancePage, {
      props: {
        loadAppearance: async () => ({ theme: 'dark' as const }),
        loadLocale: async () => ({ locale: 'en' as const }),
        saveLocale,
      },
      global: { stubs: { RouterLink: true } },
    })

    await vi.waitFor(() => expect(wrapper.get('select[name="locale"]').element).toBeTruthy())
    await wrapper.get('select[name="locale"]').setValue('ru')
    await wrapper.get('select[name="locale"]').setValue('en')

    expect(saveLocale).toHaveBeenCalledTimes(1)
    acknowledgement.resolve({ locale: 'ru' })
    await vi.waitFor(() => expect(currentLocale.value).toBe('ru'))
  })

  it('does not apply a mount read captured before a newer locale acknowledgement', async () => {
    const delayedRead = deferred<{ locale: 'en' }>()
    const loadLocale = vi.fn().mockReturnValue(delayedRead.promise)
    const stale = mount(AppearancePage, {
      props: { loadAppearance: async () => ({ theme: 'dark' as const }), loadLocale },
      global: { stubs: { RouterLink: true } },
    })
    await vi.waitFor(() => expect(loadLocale).toHaveBeenCalledTimes(1))

    const acknowledgement = deferred<{ locale: 'ru' }>()
    const writer = mount(AppearancePage, {
      props: {
        loadAppearance: async () => ({ theme: 'dark' as const }),
        loadLocale: async () => ({ locale: 'en' as const }),
        saveLocale: vi.fn().mockReturnValue(acknowledgement.promise),
      },
      global: { stubs: { RouterLink: true } },
    })
    await vi.waitFor(() => expect(writer.findAll('select[name="locale"]')).toHaveLength(1))
    await writer.get('select[name="locale"]').setValue('ru')
    acknowledgement.resolve({ locale: 'ru' })
    await vi.waitFor(() => expect(currentLocale.value).toBe('ru'))

    delayedRead.resolve({ locale: 'en' })
    await vi.waitFor(() => expect(stale.findAll('[aria-live="polite"]')).toHaveLength(0))
    await vi.waitFor(() => expect(currentLocale.value).toBe('ru'))
  })

  it('does not apply a mount read captured while a locale acknowledgement is pending', async () => {
    const acknowledgement = deferred<{ locale: 'ru' }>()
    const writer = mount(AppearancePage, {
      props: {
        loadAppearance: async () => ({ theme: 'dark' as const }),
        loadLocale: async () => ({ locale: 'en' as const }),
        saveLocale: vi.fn().mockReturnValue(acknowledgement.promise),
      },
      global: { stubs: { RouterLink: true } },
    })
    await vi.waitFor(() => expect(writer.findAll('select[name="locale"]')).toHaveLength(1))
    await writer.get('select[name="locale"]').setValue('ru')

    const delayedRead = deferred<{ locale: 'en' }>()
    const loadLocale = vi.fn().mockReturnValue(delayedRead.promise)
    const stale = mount(AppearancePage, {
      props: { loadAppearance: async () => ({ theme: 'dark' as const }), loadLocale },
      global: { stubs: { RouterLink: true } },
    })
    await vi.waitFor(() => expect(loadLocale).toHaveBeenCalledTimes(1))
    acknowledgement.resolve({ locale: 'ru' })
    await vi.waitFor(() => expect(currentLocale.value).toBe('ru'))

    delayedRead.resolve({ locale: 'en' })
    await vi.waitFor(() => expect(stale.findAll('[aria-live="polite"]')).toHaveLength(0))
    await vi.waitFor(() => expect(currentLocale.value).toBe('ru'))
  })

  it.each([
    ['mismatched acknowledgement', async () => ({ locale: 'en' as const })],
    ['malformed acknowledgement', async () => undefined],
    ['symbol acknowledgement extra', async () => ({ locale: 'ru' as const, [Symbol('extra')]: true })],
    ['non-enumerable acknowledgement extra', async () => {
      const acknowledgement = { locale: 'ru' as const }
      Object.defineProperty(acknowledgement, 'extra', { value: true })
      return acknowledgement
    }],
    ['rejected acknowledgement', async () => { throw new Error('rejected') }],
  ])('keeps the prior locale when the owner returns a %s', async (_case, saveLocale) => {
    const wrapper = mount(AppearancePage, {
      props: {
        loadAppearance: async () => ({ theme: 'dark' as const }),
        loadLocale: async () => ({ locale: 'en' as const }),
        saveLocale: saveLocale as never,
      },
      global: { stubs: { RouterLink: true } },
    })

    await vi.waitFor(() => expect(wrapper.get('select[name="locale"]').element).toBeTruthy())
    await wrapper.get('select[name="locale"]').setValue('ru')

    await vi.waitFor(() => expect(wrapper.get('[role="alert"]').text()).toContain('could not be saved'))
    expect(currentLocale.value).toBe('en')
    expect((wrapper.get('select[name="locale"]').element as HTMLSelectElement).value).toBe('en')
  })
})
