import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import { currentLocale } from '@/shared/i18n'
import TaskRunInventoryPage from './TaskRunInventoryPage.vue'

describe('TaskRunInventoryPage', () => {
  it('renders only the honest unavailable state without sample task run data', () => {
    const wrapper = mount(TaskRunInventoryPage)

    expect(wrapper.get('[data-capability="task-run-inventory"]').text()).toContain('unavailable')
    expect(wrapper.find('[data-summary-value]').exists()).toBe(false)
    expect(wrapper.find('table').exists()).toBe(false)
    expect(wrapper.text()).not.toMatch(/Desktop foundation|Runtime contract audit|Showing \d/)
  })

  it('does not render unavailable controls as disabled actions', () => {
    const wrapper = mount(TaskRunInventoryPage)

    expect(wrapper.findAll('[data-inventory-control]')).toHaveLength(0)
    expect(wrapper.find('input[type="search"]').exists()).toBe(false)
    expect(wrapper.findAll('button')).toHaveLength(0)
  })

  it('keeps the capability state as the page content', () => {
    const wrapper = mount(TaskRunInventoryPage)
    const content = wrapper.get('.task-run-inventory-page__content')
    const children = Array.from(content.element.children)
    const banner = wrapper.get('[data-capability="task-run-inventory"]')

    expect(children).toEqual([banner.element])
    expect(wrapper.get('details').text()).toContain('task-run-inventory')
  })

  it('localizes inventory copy and accessible controls in Russian', () => {
    const previousLocale = currentLocale.value
    currentLocale.value = 'ru'
    try {
      const wrapper = mount(TaskRunInventoryPage)

      expect(wrapper.get('[data-capability="task-run-inventory"]').text()).toContain('Capability runtime недоступна')
      expect(wrapper.get('h1').text()).toBe('Запуски задач')
      expect(wrapper.get('summary').text()).toBe('Идентификатор capability')
    } finally {
      currentLocale.value = previousLocale
    }
  })
})
