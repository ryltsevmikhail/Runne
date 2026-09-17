import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import TargetCapabilityBoundary from './TargetCapabilityBoundary.vue'

describe('TargetCapabilityBoundary', () => {
  it('names the missing runtime capability without implying success', () => {
    const wrapper = mount(TargetCapabilityBoundary, {
      props: {
        title: 'Inventory unavailable',
        description: 'Runtime projection required.',
        capability: 'task-run-inventory',
      },
    })

    expect(wrapper.get('[role="status"]').text()).toContain('task-run-inventory')
    expect(wrapper.get('details').attributes('open')).toBeUndefined()
    expect(wrapper.text()).not.toContain('Ready')
  })

  it('renders supplied structural content without treating it as runtime state', () => {
    const wrapper = mount(TargetCapabilityBoundary, {
      props: {
        title: 'Inventory unavailable',
        description: 'Runtime projection required.',
        capability: 'task-run-inventory',
      },
      slots: { default: '<p>Inventory layout is unavailable.</p>' },
    })

    expect(wrapper.text()).toContain('Inventory layout is unavailable.')
  })
})
