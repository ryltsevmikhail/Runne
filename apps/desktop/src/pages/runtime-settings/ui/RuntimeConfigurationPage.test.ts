import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import { nextTick } from 'vue'

import { currentLocale } from '@/shared/i18n'

import RuntimeConfigurationPage from './RuntimeConfigurationPage.vue'

function expectCategoryControlsToResolve(wrapper: ReturnType<typeof mount>) {
  for (const button of wrapper.findAll('[data-config-section]')) {
    const panelId = button.attributes('aria-controls')

    expect(panelId).toBeTruthy()
    expect(wrapper.find(`#${panelId}`).exists()).toBe(true)
  }
}

async function expectFocusedCategoryAfterKey(
  wrapper: ReturnType<typeof mount>,
  key: string,
  categoryId: string,
) {
  const activeTab = wrapper.get('[role="tab"][aria-selected="true"]')
  const activeTabElement = activeTab.element as HTMLElement
  activeTabElement.focus()
  await activeTab.trigger('keydown', { key })
  await nextTick()

  const expectedTab = wrapper.get(`[data-config-section="${categoryId}"]`)
  expect(expectedTab.attributes('aria-selected')).toBe('true')
  expect(document.activeElement).toBe(expectedTab.element)
}

describe('runtime configuration page', () => {
  it('keeps unavailable runtime categories as local presentation only', async () => {
    const wrapper = mount(RuntimeConfigurationPage)

    expect(wrapper.get('[data-capability="runtime-configuration"]').text()).toContain('unavailable')
    expect(wrapper.findAll('[data-config-section]')).toHaveLength(6)
    expect(wrapper.get('[aria-label="Runtime configuration categories"]').attributes('role')).toBe('tablist')
    expect(wrapper.get('[aria-label="Runtime configuration categories"]').attributes('aria-orientation')).toBe('vertical')
    expect(wrapper.findAll('[data-config-section]').every(button => button.attributes('role') === 'tab')).toBe(true)
    expect(wrapper.get('[data-config-section="agents"]').attributes('aria-selected')).toBe('true')
    expect(wrapper.get('[data-config-section="models-providers"]').attributes('aria-selected')).toBe('false')
    expect(wrapper.get('button[name="save-runtime-configuration"]').attributes('disabled')).toBeDefined()
    expect(wrapper.findAll('input, select, textarea, [role="textbox"]')).toHaveLength(0)
    expect(wrapper.findAll('tr, [role="row"]')).toHaveLength(0)
    expect(wrapper.text()).not.toMatch(/Lead|Builder|Reviewer|Claude|GPT|api[- ]?key|secret|token/i)
    expectCategoryControlsToResolve(wrapper)

    await wrapper.get('[data-config-section="models-providers"]').trigger('click')

    expect(wrapper.get('[data-config-detail]').text()).toContain('Models & providers')
    expectCategoryControlsToResolve(wrapper)
    expect(wrapper.get('[data-config-section="agents"]').attributes('aria-selected')).toBe('false')
    expect(wrapper.get('[data-config-section="models-providers"]').attributes('aria-selected')).toBe('true')
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

  it('moves local tab focus with standard keyboard navigation', async () => {
    const wrapper = mount(RuntimeConfigurationPage, { attachTo: document.body })
    try {
      await expectFocusedCategoryAfterKey(wrapper, 'ArrowRight', 'models-providers')
      await expectFocusedCategoryAfterKey(wrapper, 'ArrowDown', 'runtime-profiles')
      await expectFocusedCategoryAfterKey(wrapper, 'ArrowLeft', 'models-providers')
      await expectFocusedCategoryAfterKey(wrapper, 'ArrowUp', 'agents')
      await expectFocusedCategoryAfterKey(wrapper, 'ArrowLeft', 'devices')
      await expectFocusedCategoryAfterKey(wrapper, 'ArrowRight', 'agents')
      await expectFocusedCategoryAfterKey(wrapper, 'End', 'devices')
      await expectFocusedCategoryAfterKey(wrapper, 'Home', 'agents')
      expectCategoryControlsToResolve(wrapper)
    }
    finally {
      wrapper.unmount()
    }
  })
})
