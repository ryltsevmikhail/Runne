import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import RuntimeSettingsPage from './RuntimeSettingsPage.vue'

describe('runtime settings page', () => {
  it('reports the honest unconfigured state without claiming a pending contract', () => {
    const wrapper = mount(RuntimeSettingsPage)

    expect(wrapper.text()).toContain('No runtime profile configured')
    expect(wrapper.text()).toContain('Unconfigured')
    expect(wrapper.text()).not.toContain('Contract pending')
  })
})
