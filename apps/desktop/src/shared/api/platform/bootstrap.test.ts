import { describe, expect, it } from 'vitest'

import { loadBootstrap, saveTheme } from './bootstrap'

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
})
