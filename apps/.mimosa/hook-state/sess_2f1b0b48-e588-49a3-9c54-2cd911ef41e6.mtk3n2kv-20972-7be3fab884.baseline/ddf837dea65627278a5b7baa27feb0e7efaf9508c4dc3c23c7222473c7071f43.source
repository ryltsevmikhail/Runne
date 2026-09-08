import { describe, expect, it } from 'vitest'

import { listWorkspaceChanges, readWorkspaceDiff } from './diff'

const workspaceId = '01890e00-0000-7000-8000-000000000002'

describe('workspace diff API', () => {
  it('decodes sorted bounded change entries', async () => {
    const result = await listWorkspaceChanges(workspaceId, 2, async command => {
      expect(command).toBe('list_workspace_changes')
      return { items: [{ path: 'src/main.rs', kind: 'modified', additions: 2, deletions: 1 }] }
    })
    expect(result.items[0]?.kind).toBe('modified')
  })

  it('rejects traversal before invoking the host', async () => {
    let invoked = false
    await expect(readWorkspaceDiff(workspaceId, '../secret', async () => {
      invoked = true
      return {}
    })).rejects.toThrow('Invalid workspace diff path')
    expect(invoked).toBe(false)
  })

  it('rejects inconsistent hunk line counts', async () => {
    await expect(readWorkspaceDiff(workspaceId, 'src/main.rs', async () => ({
      path: 'src/main.rs',
      kind: 'modified',
      truncated: false,
      hunks: [{ oldStart: 1, oldLines: 2, newStart: 1, newLines: 1, lines: [{ kind: 'removed', text: 'old' }] }],
    }))).rejects.toThrow('Invalid workspace diff')
  })

  it('rejects hunks that are not in canonical order', async () => {
    await expect(readWorkspaceDiff(workspaceId, 'src/main.rs', async () => ({
      path: 'src/main.rs',
      kind: 'modified',
      truncated: false,
      hunks: [
        { oldStart: 2, oldLines: 0, newStart: 2, newLines: 0, lines: [] },
        { oldStart: 1, oldLines: 0, newStart: 1, newLines: 0, lines: [] },
      ],
    }))).rejects.toThrow('Invalid workspace diff')
  })
})
