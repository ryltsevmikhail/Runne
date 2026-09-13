import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import { currentLocale } from '@/shared/i18n'
import ConversationCapabilityControls from './ConversationCapabilityControls.vue'

describe('ConversationCapabilityControls', () => {
  it('keeps unavailable controls out of the composer by default', () => {
    const wrapper = mount(ConversationCapabilityControls)

    expect(wrapper.get('[data-capability="conversation-controls"]').text()).toContain('unavailable')
    expect(wrapper.get('details').attributes('open')).toBeUndefined()
    expect(wrapper.findAll('button')).toHaveLength(0)
    expect(wrapper.text()).not.toMatch(/Builder|Reviewer|Claude|GPT|\d+%|\d+k/)
    expect(wrapper.emitted()).toEqual({})
  })

  it('discloses the concise runtime capability explanation on demand', async () => {
    const wrapper = mount(ConversationCapabilityControls)
    const summary = wrapper.get('summary')

    expect(summary.text()).toContain('unavailable')
    expect(wrapper.get('.conversation-capability-controls__description').isVisible()).toBe(false)
    await summary.trigger('click')
    expect(wrapper.get('.conversation-capability-controls__description').isVisible()).toBe(true)
  })

  it('localizes unavailable controls and their accessible names in Russian', () => {
    const previousLocale = currentLocale.value
    currentLocale.value = 'ru'
    try {
      const wrapper = mount(ConversationCapabilityControls)

      expect(wrapper.text()).toContain('недоступны')
      expect(wrapper.get('summary').text()).toContain('недоступны')
    } finally {
      currentLocale.value = previousLocale
    }
  })
})
