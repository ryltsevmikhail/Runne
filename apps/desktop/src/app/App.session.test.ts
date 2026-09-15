import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { appTheme } from '@/shared/model/theme'

const platform = vi.hoisted(() => ({
  isTauri: vi.fn(() => true),
  saveTheme: vi.fn(),
  connectRuntime: vi.fn(),
  loadBootstrap: vi.fn(),
  listenExternalActivation: vi.fn(),
  loadPendingExternalActivation: vi.fn(),
  syncNotifications: vi.fn(),
  loadOwnedLocale: vi.fn(),
}))

vi.mock('@tauri-apps/api/core', () => ({ isTauri: platform.isTauri }))
vi.mock('@/shared/api/platform/bootstrap', async importOriginal => ({
  ...await importOriginal<typeof import('@/shared/api/platform/bootstrap')>(),
  saveTheme: platform.saveTheme,
  connectRuntime: platform.connectRuntime,
  loadBootstrap: platform.loadBootstrap,
}))
vi.mock('@/shared/api/platform/external-activation', async importOriginal => ({
  ...await importOriginal<typeof import('@/shared/api/platform/external-activation')>(),
  listenExternalActivation: platform.listenExternalActivation,
  loadPendingExternalActivation: platform.loadPendingExternalActivation,
}))
vi.mock('@/shared/api/platform/notifications', async importOriginal => ({
  ...await importOriginal<typeof import('@/shared/api/platform/notifications')>(),
  syncNotifications: platform.syncNotifications,
}))
vi.mock('@/shared/i18n', async importOriginal => ({
  ...await importOriginal<typeof import('@/shared/i18n')>(),
  loadOwnedLocale: platform.loadOwnedLocale,
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

const liveBootstrap = (theme: 'dark' | 'light' = 'dark') => ({
  theme,
  runtime: 'live' as const,
  runtimeMode: 'bundled' as const,
  runtimeLifecycle: 'ready' as const,
  runtimeFailure: null,
})

describe('desktop application shell fenced bootstrap reads', () => {
  beforeEach(() => {
    appTheme.value = 'dark'
    platform.isTauri.mockReturnValue(true)
    platform.connectRuntime.mockReset().mockImplementation(async () => 'live')
    platform.loadBootstrap.mockReset()
    platform.listenExternalActivation.mockReset().mockImplementation(async () => () => {})
    platform.loadPendingExternalActivation.mockReset().mockImplementation(async () => null)
    platform.syncNotifications.mockReset().mockImplementation(async () => undefined)
    platform.loadOwnedLocale.mockReset().mockImplementation(async () => undefined)
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  async function mountApp() {
    const router = createRouter({ history: createMemoryHistory(), routes })
    await router.push('/')
    await router.isReady()
    return mount(App, { global: { plugins: [router] } })
  }

  // Drives: establish proof (#1), an initial refresh that drops authentication
  // (#2, reconnecting), a stale poll read held pending (#3), a live poll that
  // schedules automatic re-establishment (#4), and the recovery proof (#5).
  function scriptStaleRead(stalePromise: Promise<unknown>) {
    let calls = 0
    platform.loadBootstrap.mockImplementation(async () => {
      calls += 1
      if (calls === 1) return liveBootstrap()
      if (calls === 2) return { ...liveBootstrap(), runtime: 'reconnecting' as const }
      if (calls === 3) return stalePromise
      return liveBootstrap()
    })
    return () => calls
  }

  async function reachReEstablishment(calls: () => number) {
    await vi.advanceTimersByTimeAsync(1_000)
    await vi.waitFor(() => expect(calls()).toBeGreaterThanOrEqual(3))
    await vi.advanceTimersByTimeAsync(1_000)
    await vi.waitFor(() => expect(calls()).toBeGreaterThanOrEqual(5))
  }

  it('drops a stale bootstrap success delivered after a re-establishment', async () => {
    const stale = deferred<unknown>()
    const calls = scriptStaleRead(stale.promise)
    const wrapper = await mountApp()
    await vi.waitFor(() => expect(calls()).toBe(2))

    await reachReEstablishment(calls)
    stale.resolve(liveBootstrap('light'))
    await flushPromises()

    // The fenced read must not touch the owner theme or any shell projection.
    expect(wrapper.attributes('data-theme')).toBe('dark')
    expect(appTheme.value).toBe('dark')
    wrapper.unmount()
  })

  it('drops a stale bootstrap rejection delivered after a re-establishment', async () => {
    const stale = deferred<unknown>()
    const calls = scriptStaleRead(stale.promise)
    const wrapper = await mountApp()
    await vi.waitFor(() => expect(calls()).toBe(2))

    await reachReEstablishment(calls)
    stale.reject(new Error('stale read'))
    await flushPromises()

    // The fenced failure must not mark the runtime failed nor fence the session.
    expect(wrapper.find('[data-lifecycle]').attributes('data-lifecycle')).toBe('ready')
    expect(wrapper.attributes('data-theme')).toBe('dark')
    wrapper.unmount()
  })
})
