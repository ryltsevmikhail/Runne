import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import GcSidebar from './GcSidebar.vue'

const items = [
  { id: 'home', label: 'Home', icon: '🏠' },
  { id: 'settings', label: 'Settings', icon: '⚙️', badge: '3' },
  { id: 'profile', label: 'Profile' },
]

describe('GcSidebar', () => {
  it('renders all items', () => {
    const wrapper = mount(GcSidebar, { props: { items } })
    const buttons = wrapper.findAll('.gc-sidebar-item')
    expect(buttons).toHaveLength(3)
  })

  it('activeItem gets active class', () => {
    const wrapper = mount(GcSidebar, {
      props: { items, activeItem: 'settings' },
    })
    const activeButton = wrapper.find('.gc-sidebar-item--active')
    expect(activeButton.exists()).toBe(true)
    expect(activeButton.text()).toContain('Settings')
  })

  it('collapsed hides labels', () => {
    const wrapper = mount(GcSidebar, {
      props: { items, collapsed: true },
    })
    expect(wrapper.find('.gc-sidebar-label').exists()).toBe(false)
  })

  it('emits navigate on click with correct id', async () => {
    const wrapper = mount(GcSidebar, { props: { items } })
    const firstButton = wrapper.findAll('.gc-sidebar-item')[0]
    await firstButton.trigger('click')
    expect(wrapper.emitted('navigate')).toBeTruthy()
    expect(wrapper.emitted('navigate')![0]).toEqual(['home'])
  })

  it('renders badges when not collapsed', () => {
    const wrapper = mount(GcSidebar, { props: { items } })
    const badge = wrapper.find('.gc-sidebar-badge')
    expect(badge.exists()).toBe(true)
    expect(badge.text()).toBe('3')
  })

  it('collapsed width is 56px', () => {
    const wrapper = mount(GcSidebar, {
      props: { items, collapsed: true },
    })
    expect(wrapper.attributes('class')).toContain('gc-sidebar--collapsed')
  })
})
