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

import { currentLocale } from '@/shared/i18n'
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
    const settingsButton = wrapper.get('.gc-sidebar-item:nth-of-type(3)')

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
    const settingsButton = wrapper.get('.gc-sidebar-item:nth-of-type(3)')

    await projectsButton.trigger('click')
    await flushPromises()
    expect(router.currentRoute.value.path).toBe('/')
    await settingsButton.trigger('click')
    await flushPromises()
    expect(router.currentRoute.value.path).toBe('/settings/runtimes')
  })

  it('routes the Task runs sidebar item through Vue Router', async () => {
    const router = createRouter({
      history: createMemoryHistory(),
      routes,
    })
    await router.push('/')
    await router.isReady()

    const wrapper = mount(App, {
      global: { plugins: [router] },
    })
    const taskRunsButton = wrapper.findAll('.gc-sidebar-item')[1]!

    expect(taskRunsButton.text()).toContain('Task runs')
    expect(taskRunsButton.get('svg').attributes('aria-hidden')).toBe('true')
    await taskRunsButton.trigger('click')
    await flushPromises()
    expect(router.currentRoute.value.path).toBe('/task-runs')
  })

  it('localizes the Task runs sidebar accessible name in Russian', async () => {
    const previousLocale = currentLocale.value
    currentLocale.value = 'ru'
    try {
      const router = createRouter({
        history: createMemoryHistory(),
        routes,
      })
      await router.push('/')
      await router.isReady()

      const wrapper = mount(App, {
        global: { plugins: [router] },
      })

      expect(wrapper.get('[aria-label="Запуски задач"]').text()).toContain('Запуски задач')
    } finally {
      currentLocale.value = previousLocale
    }
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

  it.each([
    '/recovery',
    '/settings/runtime-configuration',
    '/workspaces/01890e00-0000-7000-8000-000000000002',
  ])('keeps exactly one main landmark on %s', async (path) => {
    const router = createRouter({
      history: createMemoryHistory(),
      routes,
    })
    await router.push(path)
    await router.isReady()

    const wrapper = mount(App, {
      global: { plugins: [router] },
    })

    expect(wrapper.findAll('main')).toHaveLength(1)
  })
})
