import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import { currentLocale } from '@/shared/i18n'
import ConversationCapabilityControls from './ConversationCapabilityControls.vue'

describe('ConversationCapabilityControls', () => {
  it('renders unavailable presentation controls without capability values or events', () => {
    const wrapper = mount(ConversationCapabilityControls)
    const controls = wrapper.findAll('button')

    expect(wrapper.get('[data-capability="conversation-controls"]').text()).toContain('unavailable')
    expect(controls).toHaveLength(5)
    expect(controls.every(control => control.attributes('disabled') !== undefined)).toBe(true)
    expect(wrapper.text()).not.toMatch(/Builder|Reviewer|Claude|GPT|\d+%|\d+k/)
    expect(wrapper.emitted()).toEqual({})
  })

  it('describes every unavailable control with the visible explanation', () => {
    const wrapper = mount(ConversationCapabilityControls)
    const description = wrapper.get('#conversation-controls-unavailable')

    expect(description.isVisible()).toBe(true)
    expect(description.text()).toContain('unavailable')
    expect(wrapper.findAll('button').every(control =>
      control.attributes('aria-describedby') === description.attributes('id'))).toBe(true)
  })

  it('localizes unavailable controls and their accessible names in Russian', () => {
    const previousLocale = currentLocale.value
    currentLocale.value = 'ru'
    try {
      const wrapper = mount(ConversationCapabilityControls)

      expect(wrapper.text()).toContain('недоступны')
      expect(wrapper.get('button').attributes('aria-label')).toBe('Команды недоступны')
    } finally {
      currentLocale.value = previousLocale
    }
  })
})
