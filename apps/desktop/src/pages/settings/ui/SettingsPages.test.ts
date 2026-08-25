import { flushPromises, mount } from '@vue/test-utils'
import type { Component } from 'vue'
import { describe, expect, it } from 'vitest'

import DevicesPage from '@/pages/devices/ui/DevicesPage.vue'
import ProvidersPage from '@/pages/providers/ui/ProvidersPage.vue'
import ShortcutsPage from '@/pages/shortcuts/ui/ShortcutsPage.vue'
import UpdatesPage from '@/pages/updates/ui/UpdatesPage.vue'

import type { SettingsPageAdapter, SettingsPageSnapshot } from '../model/page-state'
import SettingsPage from './SettingsPage.vue'

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>(value => { resolve = value })
  return { promise, resolve }
}

function adapter(snapshot: SettingsPageSnapshot): SettingsPageAdapter {
  return { load: async () => snapshot }
}

const pages: readonly {
  readonly component: Component
  readonly title: string
  readonly normalLabel: string
}[] = [
  { component: SettingsPage, title: 'Settings', normalLabel: 'Desktop preferences' },
  { component: ShortcutsPage, title: 'Keyboard shortcuts', normalLabel: 'Open command palette' },
  { component: ProvidersPage, title: 'Providers', normalLabel: 'OpenAI' },
  { component: DevicesPage, title: 'Devices', normalLabel: 'This device' },
  { component: UpdatesPage, title: 'Updates', normalLabel: 'Up to date' },
]

describe.each(pages)('$title page', ({ component, title, normalLabel }) => {
  it('renders safe normal metadata from its typed adapter', async () => {
    const wrapper = mount(component, {
      props: { adapter: adapter({ kind: 'ready', items: [{ label: normalLabel, detail: 'Safe status' }] }) },
    })
    await flushPromises()

    expect(wrapper.get('h1').text()).toBe(title)
    expect(wrapper.text()).toContain(normalLabel)
    expect(wrapper.text()).toContain('Safe status')
  })

  it('announces loading while the adapter is pending', () => {
    const pending = deferred<SettingsPageSnapshot>()
    const wrapper = mount(component, { props: { adapter: { load: () => pending.promise } } })

    expect(wrapper.get('[aria-live="polite"]').text()).toContain(`Loading ${title.toLowerCase()}`)
  })

  it('fails closed when the adapter reports unavailable', async () => {
    const wrapper = mount(component, {
      props: { adapter: adapter({ kind: 'unavailable', message: 'The desktop owner is unavailable.' }) },
    })
    await flushPromises()

    expect(wrapper.get('[role="alert"]').text()).toContain('The desktop owner is unavailable.')
  })

  it('recovers only after the typed recovery adapter returns a fresh snapshot', async () => {
    let recoveries = 0
    const wrapper = mount(component, {
      props: {
        adapter: {
          load: async () => ({ kind: 'recovery', message: 'Reconnect to the desktop owner.' }),
          recover: async () => {
            recoveries += 1
            return { kind: 'ready', items: [{ label: normalLabel, detail: 'Recovered status' }] }
          },
        },
      },
    })
    await flushPromises()

    expect(wrapper.get('[role="status"]').text()).toContain('Reconnect to the desktop owner.')
    await wrapper.get('button').trigger('click')
    await flushPromises()

    expect(recoveries).toBe(1)
    expect(wrapper.text()).toContain('Recovered status')
  })
})

describe('ShortcutsPage owner editor', () => {
  it('reads bindings and saves a non-conflicting change', async () => {
    const save = async (bindings: { commandPalette: string; openProject: string }) => bindings
    const wrapper = mount(ShortcutsPage, {
      props: {
        loadBindings: async () => ({ commandPalette: 'Ctrl+P', openProject: 'Ctrl+O' }),
        saveBindings: save,
      },
    })
    await flushPromises()

    await wrapper.get('input[name="commandPalette"]').setValue('Ctrl+Shift+P')
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(wrapper.text()).toContain('Keyboard shortcuts')
    expect(wrapper.get('[role="status"]').text()).toContain('Saved')
  })
})

describe('DevicesPage owner projection', () => {
  it('renders safe runtime metadata without native handles', async () => {
    const wrapper = mount(DevicesPage, {
      props: {
        loadDeviceStatus: async () => ({
          connection: 'live',
          authenticated: true,
          runtimeVersion: '0.1.0',
          launchGeneration: 4,
        }),
      },
    })
    await flushPromises()

    expect(wrapper.text()).toContain('Authenticated')
    expect(wrapper.text()).toContain('0.1.0')
    expect(wrapper.text()).not.toContain('127.0.0.1')
  })
})

describe('ProvidersPage owner projection', () => {
  it('renders readiness without credential material', async () => {
    const wrapper = mount(ProvidersPage, {
      props: {
        loadProviderStatus: async () => [{
          providerId: 'openai',
          mode: 'openai_responses_text_v1',
          profileId: 'openai-responses-text-v1',
          profileDigest: '1'.repeat(64),
          readiness: 'credential_missing',
          selected: true,
        }],
      },
    })
    await flushPromises()

    expect(wrapper.text()).toContain('credential_missing')
    expect(wrapper.text()).not.toContain('token')
  })
})

describe('UpdatesPage owner projection', () => {
  it('renders the fail-closed native status without an artifact path', async () => {
    const wrapper = mount(UpdatesPage, {
      props: {
        loadUpdateStatus: async () => ({
          state: 'unavailable',
          currentVersion: '0.1.0',
          availableVersion: null,
          artifactSha256: null,
          reason: 'metadata_source_unavailable',
        }),
      },
    })
    await flushPromises()

    expect(wrapper.text()).toContain('metadata_source_unavailable')
    expect(wrapper.text()).not.toContain('/')
  })

  it('requires explicit confirmation before preparing a staged update', async () => {
    let confirmed = false
    const wrapper = mount(UpdatesPage, {
      props: {
        loadUpdateStatus: async () => ({
          state: 'staged',
          currentVersion: '0.1.0',
          availableVersion: '0.2.0',
          artifactSha256: 'a'.repeat(64),
          reason: null,
        }),
        prepareUpdateInstall: async value => {
          confirmed = value
          return {
            state: 'restart_required',
            currentVersion: '0.1.0',
            availableVersion: '0.2.0',
            artifactSha256: 'a'.repeat(64),
            reason: null,
          }
        },
      },
    })
    await flushPromises()

    const button = wrapper.get('button')
    expect(button.attributes('disabled')).toBeDefined()
    await wrapper.get('input[type="checkbox"]').setValue(true)
    await button.trigger('click')
    await flushPromises()

    expect(confirmed).toBe(true)
    expect(wrapper.text()).toContain('Restart the desktop')
  })
})
