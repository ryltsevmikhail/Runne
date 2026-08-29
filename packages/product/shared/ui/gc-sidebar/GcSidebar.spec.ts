import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import { h, markRaw } from 'vue'
import GcSidebar from './GcSidebar.vue'

const FolderKanbanFixture = markRaw({ render: () => h('svg') })
const SettingsFixture = markRaw({ render: () => h('svg') })

const items = [
  { id: 'home', label: 'Home', icon: FolderKanbanFixture },
  { id: 'settings', label: 'Settings', icon: SettingsFixture, badge: '3' },
  { id: 'profile', label: 'Profile' },
]

describe('GcSidebar', () => {
  it('renders the Runne lockup and route-glyph assets in its brand header', () => {
    const wrapper = mount(GcSidebar, { props: { items } })
    const darkLockup = wrapper.get('.gc-sidebar-brand-lockup--dark')
    const lightLockup = wrapper.get('.gc-sidebar-brand-lockup--light')
    const glyph = wrapper.get('.gc-sidebar-brand-glyph')

    expect(darkLockup.attributes('src')).toMatch(/^data:image\/svg\+xml/)
    expect(darkLockup.attributes('alt')).toBe('Runne')
    expect(lightLockup.attributes('src')).toMatch(/^data:image\/svg\+xml/)
    expect(lightLockup.attributes('alt')).toBe('Runne')
    expect(glyph.attributes('src')).toMatch(/^data:image\/svg\+xml/)
    expect(glyph.attributes('alt')).toBe('')
  })

  it('navigates to projects when its Runne brand control is pressed', async () => {
    const wrapper = mount(GcSidebar, { props: { items } })

    await wrapper.get('.gc-sidebar-brand').trigger('click')

    expect(wrapper.emitted('navigate')?.[0]).toEqual(['projects'])
  })

  it('renders all items', () => {
    const wrapper = mount(GcSidebar, { props: { items } })
    const buttons = wrapper.findAll('.gc-sidebar-item')
    expect(buttons).toHaveLength(3)
  })

  it('renders supplied icon components as decorative SVGs', () => {
    const wrapper = mount(GcSidebar, { props: { items } })
    const buttons = wrapper.findAll('.gc-sidebar-item')

    expect(buttons[0].get('svg').attributes('aria-hidden')).toBe('true')
    expect(buttons[1].get('svg').attributes('aria-hidden')).toBe('true')
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

  it('collapsed buttons have aria-label with item label', () => {
    const wrapper = mount(GcSidebar, {
      props: { items, collapsed: true },
    })
    const buttons = wrapper.findAll('.gc-sidebar-item')
    expect(buttons[0].attributes('aria-label')).toBe('Home')
    expect(buttons[1].attributes('aria-label')).toBe('Settings')
    // Profile has no icon but should still get aria-label in collapsed mode
    expect(buttons[2].attributes('aria-label')).toBe('Profile')
  })

  it('exposes item labels when responsive CSS hides their text', () => {
    const wrapper = mount(GcSidebar, { props: { items } })
    const buttons = wrapper.findAll('.gc-sidebar-item')

    expect(buttons[0].attributes('aria-label')).toBe('Home')
    expect(buttons[1].attributes('aria-label')).toBe('Settings')
  })

  it('collapsed width is 56px', () => {
    const wrapper = mount(GcSidebar, {
      props: { items, collapsed: true },
    })
    expect(wrapper.attributes('class')).toContain('gc-sidebar--collapsed')
  })
})
