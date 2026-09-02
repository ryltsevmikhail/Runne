import { describe, expect, it } from 'vitest'

import { openWorkspaceEditor } from './open-editor'

const workspaceId = '01890e00-0000-7000-8000-000000000002'

describe('open workspace editor', () => {
  it('sends only the workspace id and relative file reference', async () => {
    const receipt = await openWorkspaceEditor(workspaceId, 'src/main.rs', async (command, args) => {
      expect(command).toBe('open_workspace_editor')
      expect(args).toEqual({ workspaceId, relativePath: 'src/main.rs' })
      return { workspaceId, target: 'system_default' }
    })

    expect(receipt).toEqual({ workspaceId, target: 'system_default' })
  })

  it('rejects traversal before invoking the host', async () => {
    let invoked = false
    await expect(openWorkspaceEditor(workspaceId, '../main.rs', async () => {
      invoked = true
      return { workspaceId, target: 'system_default' }
    })).rejects.toThrow('Invalid editor file path')
    expect(invoked).toBe(false)
  })
})
