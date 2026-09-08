import { describe, expect, it } from 'vitest'

import {
  createCanonicalProject,
  createCanonicalWorkspace,
  openCanonicalWorkspace,
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

  it('creates a canonical workspace through a typed runtime mutation', async () => {
    const ack = await createCanonicalWorkspace(project.projectId, 'docs', async (command, args) => {
      expect(command).toBe('create_runtime_workspace')
      expect(args).toEqual({ projectId: project.projectId, displayName: 'docs' })
      return { workspaceId: workspace.workspaceId, newVersion: 1 }
    })

    expect(ack).toEqual({ workspaceId: workspace.workspaceId, newVersion: 1 })
  })

  it('creates a canonical project through a host-generated opaque ID', async () => {
    const ack = await createCanonicalProject('selected-folder', async (command, args) => {
      expect(command).toBe('create_runtime_project')
      expect(args).toEqual({ displayName: 'selected-folder' })
      return { projectId: project.projectId, newVersion: 1 }
    })

    expect(ack).toEqual({ projectId: project.projectId, newVersion: 1 })
  })

  it('opens a closed canonical workspace at its exact version', async () => {
    const ack = await openCanonicalWorkspace(workspace.workspaceId, workspace.version, async (command, args) => {
      expect(command).toBe('open_runtime_workspace')
      expect(args).toEqual({ workspaceId: workspace.workspaceId, expectedVersion: workspace.version })
      return { workspaceId: workspace.workspaceId, newVersion: workspace.version + 1 }
    })

    expect(ack).toEqual({ workspaceId: workspace.workspaceId, newVersion: workspace.version + 1 })
  })

  it('rejects invalid workspace mutation input before IPC', async () => {
    let invoked = false
    await expect(createCanonicalWorkspace('7', 'docs', async () => {
      invoked = true
      return null
    })).rejects.toThrow('Invalid canonical workspace mutation')
    await expect(createCanonicalWorkspace(project.projectId, '\u0000', async () => {
      invoked = true
      return null
    })).rejects.toThrow('Invalid canonical workspace mutation')
    expect(invoked).toBe(false)
  })

  it('rejects invalid project mutation input before IPC', async () => {
    let invoked = false
    await expect(createCanonicalProject('', async () => {
      invoked = true
      return null
    })).rejects.toThrow('Invalid canonical project mutation')
    expect(invoked).toBe(false)
  })
})
