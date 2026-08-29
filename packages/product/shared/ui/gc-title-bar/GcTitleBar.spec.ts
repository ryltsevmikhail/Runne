import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import GcTitleBar from './GcTitleBar.vue'

describe('GcTitleBar', () => {
  it('renders 3 macOS window control dots', () => {
    const wrapper = mount(GcTitleBar)
    const dots = wrapper.findAll('.gc-title-bar-dot')
    expect(dots).toHaveLength(3)
    expect(dots[0].attributes('class')).toContain('gc-title-bar-dot--close')
    expect(dots[1].attributes('class')).toContain('gc-title-bar-dot--minimize')
    expect(dots[2].attributes('class')).toContain('gc-title-bar-dot--maximize')
  })

  it('renders brand lockup text', () => {
    const wrapper = mount(GcTitleBar)
    const lockup = wrapper.find('.gc-title-bar-lockup')
    expect(lockup.exists()).toBe(true)
    expect(lockup.text()).toBe('Runne.')
  })

  it('renders brand slot', () => {
    const wrapper = mount(GcTitleBar, {
      slots: { brand: '<span class="custom-brand">MyApp</span>' },
    })
    expect(wrapper.find('.gc-title-bar-lockup').exists()).toBe(false)
    expect(wrapper.find('.custom-brand').exists()).toBe(true)
    expect(wrapper.find('.custom-brand').text()).toBe('MyApp')
  })

  it('has correct height', () => {
    const wrapper = mount(GcTitleBar)
    expect(wrapper.attributes('class')).toContain('gc-title-bar')
  })
})
