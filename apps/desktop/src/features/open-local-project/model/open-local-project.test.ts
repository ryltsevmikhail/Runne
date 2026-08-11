import { describe, expect, it } from 'vitest'

import { selectAndOpenLocalProject, selectAndPrepareLocalProject } from './open-local-project'

const selection = { reference: 'a'.repeat(64) } as const

describe('open local project', () => {
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
})
