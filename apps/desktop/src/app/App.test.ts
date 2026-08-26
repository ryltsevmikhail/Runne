import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { appTheme } from '@/shared/model/theme'

const nativeTheme = vi.hoisted(() => ({
  isTauri: vi.fn(() => false),
  saveTheme: vi.fn(),
}))

vi.mock('@tauri-apps/api/core', () => ({ isTauri: nativeTheme.isTauri }))
vi.mock('@/shared/api/platform/bootstrap', async importOriginal => ({
  ...await importOriginal<typeof import('@/shared/api/platform/bootstrap')>(),
  saveTheme: nativeTheme.saveTheme,
}))

import App from './App.vue'
import { routes } from './router'

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason?: unknown) => void
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, reject, resolve }
}

describe('desktop application shell', () => {
  beforeEach(() => {
    appTheme.value = 'dark'
    nativeTheme.isTauri.mockReturnValue(false)
    nativeTheme.saveTheme.mockReset()
  })
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
    await flushPromises()

    expect(wrapper.attributes('data-theme')).toBe('light')
    expect(wrapper.find('[aria-label="Use dark theme"]').exists()).toBe(true)
    expect(wrapper.get('.app-shell').attributes('data-theme')).toBe('light')
  })

  it('keeps the toolbar theme committed until one native acknowledgement settles', async () => {
    const acknowledgement = deferred<{ theme: 'light' }>()
    nativeTheme.saveTheme.mockReturnValue(acknowledgement.promise)
    const router = createRouter({ history: createMemoryHistory(), routes })
    await router.push('/')
    await router.isReady()
    const wrapper = mount(App, { global: { plugins: [router] } })
    nativeTheme.isTauri.mockReturnValue(true)

    const button = wrapper.get('[aria-label="Use light theme"]')
    await button.trigger('click')
    await button.trigger('click')

    expect(wrapper.attributes('data-theme')).toBe('dark')
    expect(button.attributes('aria-busy')).toBe('true')
    expect(button.attributes('disabled')).toBeDefined()
    expect(nativeTheme.saveTheme).toHaveBeenCalledTimes(1)

    acknowledgement.resolve({ theme: 'light' })
    await flushPromises()
    expect(wrapper.attributes('data-theme')).toBe('light')
    expect(wrapper.get('[aria-label="Use dark theme"]').attributes('aria-busy')).toBe('false')
  })

  it('keeps the toolbar theme unchanged after a deferred native rejection', async () => {
    const acknowledgement = deferred<{ theme: 'light' }>()
    nativeTheme.saveTheme.mockReturnValue(acknowledgement.promise)
    const router = createRouter({ history: createMemoryHistory(), routes })
    await router.push('/')
    await router.isReady()
    const wrapper = mount(App, { global: { plugins: [router] } })
    nativeTheme.isTauri.mockReturnValue(true)

    await wrapper.get('[aria-label="Use light theme"]').trigger('click')
    expect(wrapper.attributes('data-theme')).toBe('dark')
    acknowledgement.reject(new Error('owner rejected'))
    await flushPromises()

    expect(wrapper.attributes('data-theme')).toBe('dark')
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
