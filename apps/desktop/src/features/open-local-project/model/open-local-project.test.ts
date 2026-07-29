import { describe, expect, it } from 'vitest'

import { selectAndOpenLocalProject } from './open-local-project'

const project = {
  id: 7,
  name: 'gocode-ui',
  path: '/workspace/gocode-ui',
  lastOpenedAt: 1_753_500_000_000,
} as const

describe('open local project', () => {
  it('persists the directory selected by the native picker', async () => {
    const opened = await selectAndOpenLocalProject(
      async () => '/workspace/gocode-ui',
      async path => ({
        ...project,
        path,
      }),
    )

    expect(opened).toEqual(project)
  })

  it('does not mutate project state when the native picker is cancelled', async () => {
    let mutationAttempted = false

    const opened = await selectAndOpenLocalProject(
      async () => null,
      async () => {
        mutationAttempted = true
        return project
      },
    )

    expect(opened).toBeNull()
    expect(mutationAttempted).toBe(false)
  })
})
