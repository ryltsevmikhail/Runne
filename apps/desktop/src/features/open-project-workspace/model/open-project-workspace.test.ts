import { describe, expect, it, vi } from 'vitest'

import type { CanonicalProject, CanonicalProjectDetails } from '@/entities/project'

import { ProjectWorkspaceOpenError, openProjectWorkspace } from './open-project-workspace'

const project: CanonicalProject = {
  projectId: '01890e00-0000-7000-8000-000000000001',
  displayName: 'gocode-ui',
  version: 1,
  archived: false,
}
const workspace = {
  workspaceId: '01890e00-0000-7000-8000-000000000002',
  projectId: project.projectId,
  displayName: 'gocode-ui',
  version: 2,
  open: true,
} as const
const details: CanonicalProjectDetails = { project, workspaces: [workspace] }

function navigation() {
  return {
    openWorkspace: vi.fn(async () => {}),
    openProjectDetails: vi.fn(async () => {}),
  }
}

describe('open project workspace', () => {
  it('opens the single canonical workspace directly', async () => {
    const navigate = navigation()

    await expect(openProjectWorkspace(project, () => true, navigate, async () => details))
      .resolves.toBe('workspace')

    expect(navigate.openWorkspace).toHaveBeenCalledWith(workspace.workspaceId)
    expect(navigate.openProjectDetails).not.toHaveBeenCalled()
  })

  it('opens a closed workspace through the versioned public mutation', async () => {
    const navigate = navigation()
    const openWorkspace = vi.fn(async () => ({ workspaceId: workspace.workspaceId, newVersion: 3 }))

    await openProjectWorkspace(project, () => true, navigate,
      async () => ({ project, workspaces: [{ ...workspace, open: false }] }), openWorkspace)

    expect(openWorkspace).toHaveBeenCalledWith(workspace.workspaceId, workspace.version)
    expect(navigate.openWorkspace).toHaveBeenCalledWith(workspace.workspaceId)
  })

  it.each([
    ['archived', { ...project, archived: true }, details],
    ['zero workspaces', project, { project, workspaces: [] }],
    ['multiple workspaces', project, { project, workspaces: [workspace, { ...workspace, workspaceId: '01890e00-0000-7000-8000-000000000003' }] }],
  ] as const)('opens project management for %s projects', async (_caseName, selected, loaded) => {
    const navigate = navigation()

    await expect(openProjectWorkspace(selected, () => true, navigate, async () => loaded))
      .resolves.toBe('project-details')

    expect(navigate.openProjectDetails).toHaveBeenCalledWith(selected.projectId)
    expect(navigate.openWorkspace).not.toHaveBeenCalled()
  })

  it('fails closed when the runtime goes stale before navigation', async () => {
    const navigate = navigation()
    let live = true

    await expect(openProjectWorkspace(project, () => live, navigate, async () => {
      live = false
      return details
    })).rejects.toBeInstanceOf(ProjectWorkspaceOpenError)

    expect(navigate.openWorkspace).not.toHaveBeenCalled()
  })

  it('does not navigate after opening a workspace in a stale runtime', async () => {
    const navigate = navigation()
    let live = true

    await expect(openProjectWorkspace(project, () => live, navigate,
      async () => ({ project, workspaces: [{ ...workspace, open: false }] }),
      async () => {
        live = false
        return { workspaceId: workspace.workspaceId, newVersion: 3 }
      },
    )).rejects.toBeInstanceOf(ProjectWorkspaceOpenError)

    expect(navigate.openWorkspace).not.toHaveBeenCalled()
  })
})
