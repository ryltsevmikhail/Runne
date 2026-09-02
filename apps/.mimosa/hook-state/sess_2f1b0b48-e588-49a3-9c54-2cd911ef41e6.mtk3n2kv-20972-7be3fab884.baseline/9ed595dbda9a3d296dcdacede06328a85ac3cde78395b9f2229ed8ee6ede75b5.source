import { describe, expect, it } from 'vitest'

import { listWorkspaceFiles, readWorkspaceFile } from './files'

const workspaceId = '01890e00-0000-7000-8000-000000000002'

describe('workspace file API', () => {
  it('decodes a bounded sorted runtime page', async () => {
    const result = await listWorkspaceFiles(workspaceId, '', 2, async (command) => {
      expect(command).toBe('list_workspace_files')
      return {
        items: [
          { path: 'README.md', kind: 'file', sizeBytes: 7 },
          { path: 'src', kind: 'directory', sizeBytes: 0 },
        ],
      }
    })

    expect(result.items[0]?.path).toBe('README.md')
    expect(result.items[1]?.kind).toBe('directory')
  })

  it('rejects traversal before invoking the host', async () => {
    let invoked = false
    await expect(listWorkspaceFiles(workspaceId, '../', 10, async () => {
      invoked = true
      return { items: [] }
    })).rejects.toThrow('Invalid workspace file path')
    expect(invoked).toBe(false)
  })

  it('validates content size and path identity', async () => {
    const content = await readWorkspaceFile(workspaceId, 'src/main.rs', async () => ({
      path: 'src/main.rs',
      content: 'fn main() {}',
      sizeBytes: 12,
    }))
    expect(content.sizeBytes).toBe(12)

    await expect(readWorkspaceFile(workspaceId, 'src/main.rs', async () => ({
      path: 'other.rs',
      content: 'x',
      sizeBytes: 1,
    }))).rejects.toThrow('Invalid workspace file content')
  })
})
