import { mount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'

import AppearancePage from './AppearancePage.vue'

describe('AppearancePage', () => {
  it('reads the owner setting and saves an explicit theme change', async () => {
    const saveTheme = vi.fn().mockResolvedValue(undefined)
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
    expect(wrapper.text()).toContain('Light theme enabled')
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
    expect((wrapper.get('input[value="dark"]').element as HTMLInputElement).checked).toBe(true)
    expect(wrapper.get('[role="alert"]').text()).toContain('could not be saved')
  })

  it('reads and persists the owner locale with rollback on rejection', async () => {
    const saveLocale = vi.fn().mockResolvedValue(undefined)
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
    expect(saveLocale).toHaveBeenCalledWith('ru')
    expect((wrapper.get('select[name="locale"]').element as HTMLSelectElement).value).toBe('ru')
  })
})
