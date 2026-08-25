import { describe, expect, it } from 'vitest'

import {
  getCanonicalProject,
  getCanonicalWorkspace,
  listCanonicalProjects,
} from './canonical-projects'

const project = {
  projectId: '01890e00-0000-7000-8000-000000000001',
  displayName: 'gocode-ui',
  version: 1,
  archived: false,
} as const

const workspace = {
  workspaceId: '01890e00-0000-7000-8000-000000000002',
  projectId: project.projectId,
  displayName: 'gocode-ui',
  version: 2,
  open: true,
} as const

describe('canonical project IPC adapter', () => {
  it('accepts only canonical project and workspace projections', async () => {
    await expect(listCanonicalProjects(async () => [project])).resolves.toEqual([project])
    await expect(getCanonicalProject(project.projectId, async () => ({
      project,
      workspaces: [workspace],
    }))).resolves.toEqual({ project, workspaces: [workspace] })
    await expect(getCanonicalWorkspace(workspace.workspaceId, async () => workspace))
      .resolves.toEqual(workspace)
  })

  it('rejects local metadata, numeric IDs, and path-bearing projections', async () => {
    await expect(listCanonicalProjects(async () => [{
      ...project,
      lastOpenedAt: 1,
    }])).rejects.toThrow('Invalid canonical projects response')
    await expect(getCanonicalProject('7', async () => null)).rejects.toThrow(
      'Invalid canonical project identifier',
    )
    await expect(getCanonicalWorkspace(workspace.workspaceId, async () => ({
      ...workspace,
      path: '/private/root',
    }))).rejects.toThrow('Invalid canonical workspace response')
  })
})
