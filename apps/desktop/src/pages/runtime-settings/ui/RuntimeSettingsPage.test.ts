import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import RuntimeSettingsPage from './RuntimeSettingsPage.vue'

describe('runtime settings page', () => {
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
    })
    await flushPromises()

    expect(wrapper.text()).toContain('External runtime mode')
    expect(wrapper.text()).toContain('never stops or adopts')
  })
})
