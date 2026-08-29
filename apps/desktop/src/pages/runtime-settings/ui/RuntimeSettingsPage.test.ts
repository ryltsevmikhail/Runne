import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import { currentLocale } from '@/shared/i18n'

import RuntimeSettingsPage from './RuntimeSettingsPage.vue'

describe('runtime settings page', () => {
  it('renders bootstrap-backed facts as read-only without a Save action', async () => {
    const wrapper = mount(RuntimeSettingsPage, {
      props: {
        loadRuntime: async () => ({
          theme: 'dark',
          runtimeMode: 'bundled',
          runtime: 'live',
          runtimeLifecycle: 'ready',
          runtimeFailure: null,
        }),
      },
      global: { stubs: { RouterLink: true } },
    })
    await flushPromises()

    expect(wrapper.text()).toContain('IMPLEMENTED · READ ONLY')
    expect(wrapper.text()).toContain('Runtime mode')
    expect(wrapper.text()).toContain('Connection')
    expect(wrapper.text()).toContain('Lifecycle')
    expect(wrapper.text()).toContain('Actionable failure')
    expect(wrapper.text()).toContain('Endpoint editing, reconnect policy, runtime toggles, providers, devices, and reset actions')
    expect(wrapper.findAll('button').some(button => button.text().includes('Save'))).toBe(false)
  })

  it('localizes Phase 2 runtime copy through the owned catalog', async () => {
    const previousLocale = currentLocale.value
    currentLocale.value = 'ru'
    try {
      const wrapper = mount(RuntimeSettingsPage, {
        props: {
          loadRuntime: async () => ({
            theme: 'dark', runtimeMode: 'bundled', runtime: 'live', runtimeLifecycle: 'ready', runtimeFailure: null,
          }),
        },
        global: { stubs: { RouterLink: true } },
      })
      await flushPromises()

      expect(wrapper.text()).toContain('РЕАЛИЗОВАНО · ТОЛЬКО ЧТЕНИЕ')
      expect(wrapper.text()).toContain('Режим runtime')
      expect(wrapper.text()).toContain('Нет')
      expect(wrapper.text()).toContain('Изменение endpoint, политика переподключения')
    }
    finally {
      currentLocale.value = previousLocale
    }
  })

  it('reports protected bundled mode without claiming production signing', async () => {
    const wrapper = mount(RuntimeSettingsPage, {
      props: {
        loadRuntime: async () => ({
          theme: 'dark',
          runtimeMode: 'bundled',
          runtime: 'reconnecting',
          runtimeLifecycle: 'starting',
          runtimeFailure: null,
        }),
      },
      global: { stubs: { RouterLink: true } },
    })
    await flushPromises()

    expect(wrapper.text()).toContain('Protected bundled runtime')
    expect(wrapper.text()).toContain('development/ad-hoc')
    expect(wrapper.text()).not.toContain('notarized')
  })

  it('identifies external runtime as an explicit no-ownership mode', async () => {
    const wrapper = mount(RuntimeSettingsPage, {
      props: {
        loadRuntime: async () => ({
          theme: 'dark',
          runtimeMode: 'external_local',
          runtime: 'live',
          runtimeLifecycle: 'external',
          runtimeFailure: null,
        }),
      },
      global: { stubs: { RouterLink: true } },
    })
    await flushPromises()

    expect(wrapper.text()).toContain('External runtime mode')
    expect(wrapper.text()).toContain('never stops or adopts')
  })
})
