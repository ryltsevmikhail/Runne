import { flushPromises, mount } from '@vue/test-utils'
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

  it('renders Projects and Settings navigation controls with SVG icons', async () => {
    const router = createRouter({
      history: createMemoryHistory(),
      routes,
    })
    await router.push('/')
    await router.isReady()

    const wrapper = mount(App, {
      global: { plugins: [router] },
    })
    const projectsButton = wrapper.get('.gc-sidebar-item')
    const settingsButton = wrapper.get('.gc-sidebar-item:nth-of-type(2)')

    expect(projectsButton.text()).toContain('Projects')
    expect(projectsButton.get('svg').attributes('aria-hidden')).toBe('true')
    expect(settingsButton.text()).toContain('Settings')
    expect(settingsButton.get('svg').attributes('aria-hidden')).toBe('true')
  })

  it('routes sidebar navigation to Projects and Runtime Settings', async () => {
    const router = createRouter({
      history: createMemoryHistory(),
      routes,
    })
    await router.push('/settings/runtimes')
    await router.isReady()

    const wrapper = mount(App, {
      global: { plugins: [router] },
    })
    const projectsButton = wrapper.get('.gc-sidebar-item')
    const settingsButton = wrapper.get('.gc-sidebar-item:nth-of-type(2)')

    await projectsButton.trigger('click')
    await flushPromises()
    expect(router.currentRoute.value.path).toBe('/')
    await settingsButton.trigger('click')
    await flushPromises()
    expect(router.currentRoute.value.path).toBe('/settings/runtimes')
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

    expect(wrapper.get('.gc-sidebar-brand-lockup').attributes('src')).toMatch(/^data:image\/svg\+xml/)
    expect(wrapper.get('.gc-sidebar-brand-glyph').attributes('src')).toMatch(/^data:image\/svg\+xml/)
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
    expect(titleBar.get('.gc-title-bar-logo').attributes('alt')).toBe('Runne')
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

  it('expands the desktop navigation after it is collapsed', async () => {
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
    const expandButton = wrapper.get('[aria-label="Expand sidebar"]')
    await expandButton.trigger('click')

    expect(wrapper.get('aside').classes()).not.toContain('sidebar--collapsed')
    expect(wrapper.find('[aria-label="Collapse sidebar"]').exists()).toBe(true)
  })

  it('keeps narrow sidebar labels available without entering collapsed state', async () => {
    const previousWidth = window.innerWidth
    Object.defineProperty(window, 'innerWidth', { configurable: true, value: 1023 })
    const router = createRouter({
      history: createMemoryHistory(),
      routes,
    })
    await router.push('/')
    await router.isReady()

    const wrapper = mount(App, {
      global: { plugins: [router] },
    })

    expect(wrapper.get('aside').classes()).not.toContain('sidebar--collapsed')
    expect(wrapper.get('.gc-sidebar-item').attributes('aria-label')).toBe('Projects')
    expect(wrapper.get('.gc-sidebar-item:nth-of-type(2)').attributes('aria-label')).toBe('Settings')

    Object.defineProperty(window, 'innerWidth', { configurable: true, value: previousWidth })
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
