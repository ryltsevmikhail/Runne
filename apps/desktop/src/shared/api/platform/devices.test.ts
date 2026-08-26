import { describe, expect, it } from 'vitest'

import { getDeviceStatus } from './devices'

describe('device status adapter', () => {
  it('returns a newly allocated bounded owner snapshot', async () => {
    const response = {
      connection: 'live' as const,
      authenticated: true,
      runtimeVersion: '0.1.0',
      launchGeneration: 4,
    }
    const snapshot = await getDeviceStatus(async command => {
      expect(command).toBe('get_device_status')
      return response
    })
    expect(snapshot).toEqual(response)
    expect(snapshot).not.toBe(response)
  })

  it('rejects unknown connection state', async () => {
    await expect(getDeviceStatus(async () => ({
      connection: 'connected',
      authenticated: true,
      runtimeVersion: null,
      launchGeneration: null,
    }))).rejects.toThrow('Invalid device status')
  })

  it('accepts a null-prototype owner record', async () => {
    const response = Object.assign(Object.create(null), {
      connection: 'live', authenticated: true, runtimeVersion: null, launchGeneration: null,
    })

    await expect(getDeviceStatus(async () => response)).resolves.toEqual({
      connection: 'live', authenticated: true, runtimeVersion: null, launchGeneration: null,
    })
  })

  it.each([
    ['an extra enumerable field', () => ({
      connection: 'live', authenticated: true, runtimeVersion: null, launchGeneration: null, endpoint: '127.0.0.1',
    })],
    ['an extra symbol field', () => ({
      connection: 'live', authenticated: true, runtimeVersion: null, launchGeneration: null, [Symbol('secret')]: 'hidden',
    })],
    ['an extra non-enumerable field', () => {
      const value = { connection: 'live', authenticated: true, runtimeVersion: null, launchGeneration: null }
      Object.defineProperty(value, 'secret', { value: 'hidden' })
      return value
    }],
    ['an inherited required field', () => Object.assign(Object.create({ connection: 'live' }), {
      authenticated: true, runtimeVersion: null, launchGeneration: null,
    })],
    ['custom prototype metadata', () => Object.assign(Object.create({ endpoint: '127.0.0.1' }), {
      connection: 'live', authenticated: true, runtimeVersion: null, launchGeneration: null,
    })],
  ])('rejects %s', async (_case, response) => {
    await expect(getDeviceStatus(async () => response())).rejects.toThrow('Invalid device status')
  })
})
