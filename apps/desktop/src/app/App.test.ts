import { mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { describe, expect, it } from 'vitest'

import App from './App.vue'
import { routes } from './router'

describe('desktop application shell', () => {
  it('renders navigation and the selected route inside the workspace', async () => {
    const router = createRouter({
      history: createMemoryHistory(),
      routes,
    })
    await router.push('/')
    await router.isReady()

    const wrapper = mount(App, {
      global: { plugins: [router] },
    })

    expect(wrapper.get('nav').attributes('aria-label')).toBe('Primary')
    expect(wrapper.findComponent({ name: 'GcSidebar' }).exists()).toBe(true)
    expect(wrapper.get('main').text()).toContain('Projects')
  })

  it('uses the canonical Runne brand assets in the desktop shell', async () => {
    const router = createRouter({
      history: createMemoryHistory(),
      routes,
    })
    await router.push('/')
    await router.isReady()

    const wrapper = mount(App, {
      global: { plugins: [router] },
    })

    expect(wrapper.get('.brand-lockup').attributes('src')).toContain('gocode-lockup')
    expect(wrapper.get('.brand-icon').attributes('src')).toContain('gocode-app-icon')
    expect(wrapper.find('.brand-mark').exists()).toBe(false)
  })

  it('renders the documented native drag region without a duplicate title', async () => {
    const router = createRouter({
      history: createMemoryHistory(),
      routes,
    })
    await router.push('/')
    await router.isReady()

    const wrapper = mount(App, {
      global: { plugins: [router] },
    })

    const titleBar = wrapper.get('.desktop-title-bar')
    expect(titleBar.attributes('data-tauri-drag-region')).toBe('')
    expect(titleBar.text()).toContain('Runne')
  })

  it('toggles the desktop color theme from the sidebar', async () => {
    const router = createRouter({
      history: createMemoryHistory(),
      routes,
    })
    await router.push('/')
    await router.isReady()

    const wrapper = mount(App, {
      global: { plugins: [router] },
    })

    await wrapper.get('[aria-label="Use light theme"]').trigger('click')

    expect(wrapper.attributes('data-theme')).toBe('light')
    expect(wrapper.find('[aria-label="Use dark theme"]').exists()).toBe(true)
    expect(wrapper.get('.app-shell').attributes('data-theme')).toBe('light')
  })

  it('collapses the desktop navigation without hiding its accessible name', async () => {
    const router = createRouter({
      history: createMemoryHistory(),
      routes,
    })
    await router.push('/')
    await router.isReady()

    const wrapper = mount(App, {
      global: { plugins: [router] },
    })

    await wrapper.get('[aria-label="Collapse sidebar"]').trigger('click')

    expect(wrapper.get('aside').classes()).toContain('sidebar--collapsed')
    expect(wrapper.get('nav').attributes('aria-label')).toBe('Primary')
  })

  it('links the diagnostics action to the documented local route', async () => {
    const router = createRouter({
      history: createMemoryHistory(),
      routes,
    })
    await router.push('/')
    await router.isReady()

    const wrapper = mount(App, {
      global: { plugins: [router] },
    })

    expect(wrapper.get('[aria-label="Diagnostics"]').attributes('href')).toBe('/settings/diagnostics')
  })
})
