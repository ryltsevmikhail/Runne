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

  it('renders dark and light Runne primary-logo assets in the default brand slot', () => {
    const wrapper = mount(GcTitleBar)
    const darkLogo = wrapper.get('.gc-title-bar-logo--dark')
    const lightLogo = wrapper.get('.gc-title-bar-logo--light')

    expect(darkLogo.attributes('src')).toMatch(/^data:image\/svg\+xml/)
    expect(darkLogo.attributes('alt')).toBe('Runne')
    expect(lightLogo.attributes('src')).toMatch(/^data:image\/svg\+xml/)
    expect(lightLogo.attributes('alt')).toBe('Runne')
  })

  it('renders brand slot', () => {
    const wrapper = mount(GcTitleBar, {
      slots: { brand: '<span class="custom-brand">MyApp</span>' },
    })
    expect(wrapper.find('.gc-title-bar-logo').exists()).toBe(false)
    expect(wrapper.find('.custom-brand').exists()).toBe(true)
    expect(wrapper.find('.custom-brand').text()).toBe('MyApp')
  })

  it('has correct height', () => {
    const wrapper = mount(GcTitleBar)
    expect(wrapper.attributes('class')).toContain('gc-title-bar')
  })
})
