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
    expect(wrapper.get('main').text()).toContain('Projects')
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
})
