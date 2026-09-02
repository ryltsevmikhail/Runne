import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import { currentLocale } from '@/shared/i18n'
import TaskRunInventoryPage from './TaskRunInventoryPage.vue'

describe('TaskRunInventoryPage', () => {
  it('renders an unavailable inventory without sample task run data', () => {
    const wrapper = mount(TaskRunInventoryPage)
    const summaryValues = wrapper.findAll('[data-summary-value]')

    expect(wrapper.get('[data-capability="task-run-inventory"]').text()).toContain('unavailable')
    expect(summaryValues).toHaveLength(4)
    expect(summaryValues.map(cell => cell.text())).toEqual([
      'Unavailable',
      'Unavailable',
      'Unavailable',
      'Unavailable',
    ])
    expect(wrapper.findAll('tbody tr')).toHaveLength(0)
    expect(wrapper.text()).not.toMatch(/Desktop foundation|Runtime contract audit|Showing \d/)
  })

  it('keeps unsupported search and filters disabled', () => {
    const wrapper = mount(TaskRunInventoryPage)
    const controls = wrapper.findAll('[data-inventory-control]')

    expect(wrapper.get('[aria-label="Search task runs"]').attributes('disabled')).toBe('')
    expect(controls).toHaveLength(6)
    expect(controls.every(control => control.attributes('disabled') === '')).toBe(true)
  })

  it('places the capability banner before unavailable inventory surfaces', () => {
    const wrapper = mount(TaskRunInventoryPage)
    const content = wrapper.get('.task-run-inventory-page__content')
    const children = Array.from(content.element.children)
    const banner = wrapper.get('[data-capability="task-run-inventory"]')

    expect(children.indexOf(banner.element)).toBe(0)
    expect(children.indexOf(wrapper.get('.task-run-inventory-page__summary').element)).toBeGreaterThan(0)
    expect(children.indexOf(wrapper.get('.task-run-inventory-page__toolbar').element)).toBeGreaterThan(0)
    expect(wrapper.find('tfoot').exists()).toBe(false)
    expect(wrapper.get('[data-inventory-table-state]').text()).toContain('unavailable')
  })

  it('localizes inventory copy and accessible controls in Russian', () => {
    const previousLocale = currentLocale.value
    currentLocale.value = 'ru'
    try {
      const wrapper = mount(TaskRunInventoryPage)

      expect(wrapper.get('[data-summary-value]').text()).toBe('Недоступно')
      expect(wrapper.get('[aria-label="Поиск запусков задач"]').attributes('disabled')).toBe('')
    } finally {
      currentLocale.value = previousLocale
    }
  })
})
