import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import { getDeviceStatus } from '@/shared/api/platform/devices'

import DevicesPage from './DevicesPage.vue'

describe('DevicesPage', () => {
  it('fails closed when the device adapter rejects injected native metadata', async () => {
    const wrapper = mount(DevicesPage, {
      props: {
        loadDeviceStatus: () => getDeviceStatus(async () => ({
          connection: 'live',
          authenticated: true,
          runtimeVersion: '0.1.0',
          launchGeneration: 4,
          endpoint: '127.0.0.1',
          secret: 'credential',
        })),
      },
    })
    await flushPromises()

    expect(wrapper.get('[role="alert"]').text()).toContain('Device status')
    expect(wrapper.text()).not.toContain('127.0.0.1')
    expect(wrapper.text()).not.toContain('credential')
  })

  it('renders a valid safe device projection', async () => {
    const wrapper = mount(DevicesPage, {
      props: {
        loadDeviceStatus: () => getDeviceStatus(async () => ({
          connection: 'live',
          authenticated: true,
          runtimeVersion: '0.1.0',
          launchGeneration: 4,
        })),
      },
    })
    await flushPromises()

    expect(wrapper.text()).toContain('Authenticated')
    expect(wrapper.text()).toContain('0.1.0')
    expect(wrapper.find('[role="alert"]').exists()).toBe(false)
  })
})
