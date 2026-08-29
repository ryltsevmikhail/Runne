import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import { currentLocale } from '@/shared/i18n'

import RuntimeConfigurationPage from './RuntimeConfigurationPage.vue'

describe('runtime configuration page', () => {
  it('keeps unavailable runtime categories as local presentation only', async () => {
    const wrapper = mount(RuntimeConfigurationPage)

    expect(wrapper.get('[data-capability="runtime-configuration"]').text()).toContain('unavailable')
    expect(wrapper.findAll('[data-config-section]')).toHaveLength(6)
    expect(wrapper.get('button[name="save-runtime-configuration"]').attributes('disabled')).toBeDefined()
    expect(wrapper.findAll('input, select, textarea, [role="textbox"]')).toHaveLength(0)
    expect(wrapper.findAll('tr, [role="row"]')).toHaveLength(0)
    expect(wrapper.text()).not.toMatch(/Lead|Builder|Reviewer|Claude|GPT|api[- ]?key|secret|token/i)

    await wrapper.get('[data-config-section="models-providers"]').trigger('click')

    expect(wrapper.get('[data-config-detail]').text()).toContain('Models & providers')
    expect(wrapper.emitted('save')).toBeUndefined()
  })

  it('localizes category labels and unavailable save explanation', () => {
    const previousLocale = currentLocale.value
    currentLocale.value = 'ru'
    try {
      const wrapper = mount(RuntimeConfigurationPage)

      expect(wrapper.get('h1').text()).toBe('Конфигурация runtime')
      expect(wrapper.get('[aria-label="Категории конфигурации runtime"]')).toBeTruthy()
      expect(wrapper.get('button[name="save-runtime-configuration"]').attributes('aria-describedby')).toBe('runtime-configuration-save-unavailable')
      expect(wrapper.get('#runtime-configuration-save-unavailable').text()).toContain('недоступно')
    }
    finally {
      currentLocale.value = previousLocale
    }
  })
})
