import { describe, expect, it } from 'vitest'

import { connectRuntime, loadBootstrap, saveTheme } from './bootstrap'

describe('bootstrap IPC adapter', () => {
  it('accepts the closed sanitized bootstrap response', async () => {
    const state = await loadBootstrap(async () => ({
      theme: 'light',
      runtime: 'unconfigured',
    }))

    expect(state).toEqual({
      theme: 'light',
      runtime: 'unconfigured',
    })
  })

  it('rejects an unknown runtime availability', async () => {
    await expect(
      loadBootstrap(async () => ({
        theme: 'dark',
        runtime: 'connected',
      })),
    ).rejects.toThrow('Invalid bootstrap response')
  })

  it('sends a typed theme update without other settings', async () => {
    const calls: Array<[string, Record<string, unknown> | undefined]> = []

    await saveTheme('light', async (command, args) => {
      calls.push([command, args])
    })

    expect(calls).toEqual([['set_theme', { theme: 'light' }]])
  })

  it('accepts only a closed runtime state from the host connection command', async () => {
    const calls: string[] = []
    const state = await connectRuntime(async (command) => {
      calls.push(command)
      return 'live'
    })

    expect(state).toBe('live')
    expect(calls).toEqual(['connect_runtime'])

    await expect(connectRuntime(async () => 'connected')).rejects.toThrow(
      'Invalid runtime connection response',
    )
  })

  it('accepts exactly the proof-gated runtime connection states', async () => {
    const states = [
      'unconfigured',
      'profile_loaded',
      'peer_verified',
      'bootstrap_proved',
      'authenticated',
      'reconciling',
      'live',
      'reconnecting',
      'incompatible',
      'revoked',
      'resync_required',
      'fatal',
    ] as const

    for (const state of states) {
      await expect(connectRuntime(async () => state)).resolves.toBe(state)
    }

    for (const state of ['connecting', 'authenticating', 'stale']) {
      await expect(connectRuntime(async () => state)).rejects.toThrow(
        'Invalid runtime connection response',
      )
    }
  })
})
