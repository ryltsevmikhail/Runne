import { describe, expect, it } from 'vitest'

import {
  LocalProjectOpenError,
  selectAndCreateLocalProject,
  selectAndOpenLocalProject,
  selectAndPrepareLocalProject,
} from './open-local-project'

const selection = { reference: 'a'.repeat(64) } as const

describe('open local project', () => {
  it.each(['selection', 'creation', 'workspace'] as const)('reports %s failure without exposing native error data', async stage => {
    const fail = async () => { throw new Error('/private/owner/secret') }
    try {
      await selectAndCreateLocalProject(
        async () => 7,
        stage === 'selection' ? fail : async () => selection,
        stage === 'creation' ? fail : async () => ({ projectId: 'project', newVersion: 1 }),
        async () => ({ workspaceId: 'workspace', newVersion: 1 }),
        fail,
      )
      expect.unreachable()
    }
    catch (error) {
      expect(error).toBeInstanceOf(LocalProjectOpenError)
      expect(error).toMatchObject({ stage })
      expect(String(error)).not.toContain('/private/')
      expect(error).not.toHaveProperty('cause')
    }
  })

  it('gets a host-issued generation before requesting an opaque selection', async () => {
    const opened = await selectAndOpenLocalProject(async () => {
      return 7
    }, async (_requestId, rendererGeneration) => {
      expect(rendererGeneration).toBe(7)
      return selection
    })

    expect(opened).toEqual(selection)
  })

  it('returns null when the host picker is cancelled', async () => {
    const opened = await selectAndOpenLocalProject(async () => 99, async () => null)

    expect(opened).toBeNull()
  })

  it('passes an opaque selection through the strict preparation adapter', async () => {
    const prepared = await selectAndPrepareLocalProject(
      '01890e00-0000-7000-8000-000000000001',
      3,
      async () => 99,
      async (_requestId, rendererGeneration) => {
        expect(rendererGeneration).toBe(7)
        return selection
      },
      async request => {
        expect(request).toMatchObject({
          selection: selection.reference,
          rendererGeneration: 7,
          workspaceId: '01890e00-0000-7000-8000-000000000001',
          expectedVersion: 3,
        })
        return { reference: 'b'.repeat(64), summary: { displayName: 'Selected folder' } }
      },
    )

    expect(prepared).toEqual({
      reference: 'b'.repeat(64),
      summary: { displayName: 'Selected folder' },
    })
  })

  it('creates and opens a canonical project only after protected preparation', async () => {
    const calls: string[] = []
    const result = await selectAndCreateLocalProject(
      async () => 7,
      async (requestId, rendererGeneration) => {
        expect(requestId).toMatch(/^[0-9a-f-]{36}$/)
        expect(rendererGeneration).toBe(7)
        return selection
      },
      async displayName => {
        calls.push(`project:${displayName}`)
        return { projectId: '01890e00-0000-7000-8000-000000000001', newVersion: 1 }
      },
      async (projectId, displayName) => {
        calls.push(`workspace:${projectId}:${displayName}`)
        return { workspaceId: '01890e00-0000-7000-8000-000000000002', newVersion: 1 }
      },
      async request => {
        calls.push(`prepare:${request.workspaceId}:${request.expectedVersion}`)
        return { reference: 'b'.repeat(64), summary: { displayName: 'Selected folder' } }
      },
      async request => {
        calls.push(`open:${request.prepared}`)
      },
    )

    expect(result).toEqual({
      projectId: '01890e00-0000-7000-8000-000000000001',
      workspaceId: '01890e00-0000-7000-8000-000000000002',
    })
    expect(calls).toEqual([
      'project:Selected folder',
      'workspace:01890e00-0000-7000-8000-000000000001:Selected folder',
      'prepare:01890e00-0000-7000-8000-000000000002:1',
      'open:'.concat('b'.repeat(64)),
    ])
  })
})
