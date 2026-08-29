import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import RecoveryPage from './RecoveryPage.vue'

describe('RecoveryPage', () => {
  it('renders recovery as unavailable without a simulated workflow', () => {
    const wrapper = mount(RecoveryPage, {
      global: {
        stubs: {
          RouterLink: {
            props: ['to'],
            template: '<a :href="to"><slot /></a>',
          },
        },
      },
    })

    expect(wrapper.get('[data-capability="recovery-orchestration"]').text()).toContain('unavailable')
    expect(wrapper.get('a').attributes('href')).toBe('/')
    expect(wrapper.findAll('button')).toHaveLength(0)
    expect(wrapper.text()).not.toMatch(/Restoring|Validated|\d+%/)
  })
})
