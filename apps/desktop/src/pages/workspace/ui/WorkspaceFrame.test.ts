import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import WorkspaceFrame from './WorkspaceFrame.vue'

function mountFrame() {
  return mount(WorkspaceFrame, {
    slots: {
      explorer: '<p>files stay mounted</p>',
      conversation: '<p>conversation</p>',
      details: '<p>details stay mounted</p>',
    },
  })
}

describe('WorkspaceFrame', () => {
  it('keeps the conversation primary and collapses secondary panels initially', () => {
    const wrapper = mountFrame()

    expect(wrapper.get('[aria-label="Conversation"]').isVisible()).toBe(true)
    expect(wrapper.get('[aria-label="Project tree"]').isVisible()).toBe(false)
    expect(wrapper.get('[aria-label="Details"]').isVisible()).toBe(false)
    expect(wrapper.get('[aria-label="Show files"]').attributes('aria-pressed')).toBe('false')
    expect(wrapper.get('[aria-label="Show details"]').attributes('aria-pressed')).toBe('false')
  })

  it('toggles both panels without removing their slot state', async () => {
    const wrapper = mountFrame()
    const explorer = wrapper.get('#workspace-explorer')
    const details = wrapper.get('#workspace-details')

    await wrapper.get('[aria-label="Show files"]').trigger('click')
    await wrapper.get('[aria-label="Show details"]').trigger('click')

    expect(explorer.isVisible()).toBe(true)
    expect(details.isVisible()).toBe(true)
    expect(wrapper.get('[aria-label="Hide files"]').attributes('aria-pressed')).toBe('true')
    expect(wrapper.get('[aria-label="Hide details"]').attributes('aria-pressed')).toBe('true')

    await wrapper.get('[aria-label="Hide files"]').trigger('click')
    expect(wrapper.get('[aria-label="Show files"]').attributes('aria-pressed')).toBe('false')
    expect(wrapper.get('#workspace-explorer').attributes('style')).toContain('display: none')
    expect(explorer.text()).toContain('files stay mounted')
  })
})
