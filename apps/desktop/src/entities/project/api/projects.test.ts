import { describe, expect, it } from 'vitest'

import { getProject, listProjects, openLocalProject } from './projects'

const project = {
  id: 7,
  name: 'gocode-ui',
  path: '/workspace/gocode-ui',
  lastOpenedAt: 1_753_500_000_000,
} as const

describe('project IPC adapter', () => {
  it('accepts a closed project list response', async () => {
    const projects = await listProjects(async () => [project])

    expect(projects).toEqual([project])
  })

  it('opens only the selected local directory', async () => {
    const calls: Array<[string, Record<string, unknown> | undefined]> = []

    const opened = await openLocalProject('/workspace/gocode-ui', async (command, args) => {
      calls.push([command, args])
      return project
    })

    expect(opened).toEqual(project)
    expect(calls).toEqual([
      ['open_local_project', { path: '/workspace/gocode-ui' }],
    ])
  })

  it('rejects malformed project data at the renderer boundary', async () => {
    await expect(
      getProject(7, async () => ({
        ...project,
        path: null,
      })),
    ).rejects.toThrow('Invalid project response')
  })
})
