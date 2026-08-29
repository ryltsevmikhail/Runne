import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

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
})
