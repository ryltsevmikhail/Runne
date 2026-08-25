import { describe, expect, it } from 'vitest'

import { getDeviceStatus } from './devices'

describe('device status adapter', () => {
  it('accepts only the bounded owner snapshot', async () => {
    const snapshot = await getDeviceStatus(async command => {
      expect(command).toBe('get_device_status')
      return {
        connection: 'live',
        authenticated: true,
        runtimeVersion: '0.1.0',
        launchGeneration: 4,
      }
    })
    expect(snapshot.authenticated).toBe(true)
  })

  it('rejects unknown connection state', async () => {
    await expect(getDeviceStatus(async () => ({
      connection: 'connected',
      authenticated: true,
      runtimeVersion: null,
      launchGeneration: null,
    }))).rejects.toThrow('Invalid device status')
  })
})
