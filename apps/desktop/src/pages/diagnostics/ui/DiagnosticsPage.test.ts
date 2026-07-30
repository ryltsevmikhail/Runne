import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import DiagnosticsPage from './DiagnosticsPage.vue'

describe('diagnostics page', () => {
  it('renders only the bounded redacted snapshot', async () => {
    const wrapper = mount(DiagnosticsPage, {
      props: {
        loadDiagnostics: async () => ({
          appVersion: '0.1.0',
          platform: 'macos',
          databaseSchemaVersion: 3,
          databaseGeneration: 4,
          projectCount: 2,
          runtimeMode: 'external_local',
          runtime: 'unconfigured',
        }),
      },
    })
    await flushPromises()

    expect(wrapper.text()).toContain('Database generation')
    expect(wrapper.text()).toContain('4')
    expect(wrapper.text()).not.toContain('/Users/')
    expect(wrapper.text()).not.toContain('prompt')
  })

  it('shows a stable failure state without raw error details', async () => {
    const wrapper = mount(DiagnosticsPage, {
      props: {
        loadDiagnostics: async () => {
          throw new Error('/Users/private/token=secret')
        },
      },
    })
    await flushPromises()

    expect(wrapper.get('[role="alert"]').text()).toContain('Diagnostics unavailable')
    expect(wrapper.text()).not.toContain('/Users/private')
    expect(wrapper.text()).not.toContain('secret')
  })
})
