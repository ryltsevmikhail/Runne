import { describe, expect, it } from 'vitest'

import { loadShortcuts, saveShortcuts } from './shortcuts'

describe('shortcut IPC adapter', () => {
  it('validates exact bindings and requires an owner acknowledgement', async () => {
    await expect(loadShortcuts(async () => ({ commandPalette: 'Ctrl+P', openProject: 'Ctrl+O' })))
      .resolves.toEqual({ commandPalette: 'Ctrl+P', openProject: 'Ctrl+O' })
    await expect(loadShortcuts(async () => ({ commandPalette: 'Ctrl+P', openProject: 'Ctrl+P' })))
      .rejects.toThrow('Invalid shortcuts response')

    const calls: Array<[string, Record<string, unknown> | undefined]> = []
    await saveShortcuts(
      { commandPalette: 'Ctrl+P', openProject: 'Ctrl+O' },
      async (command, args) => {
        calls.push([command, args])
        return { commandPalette: 'Ctrl+P', openProject: 'Ctrl+O' }
      },
    )
    expect(calls).toEqual([['set_shortcuts', { shortcuts: { commandPalette: 'Ctrl+P', openProject: 'Ctrl+O' } }]])
  })
})
