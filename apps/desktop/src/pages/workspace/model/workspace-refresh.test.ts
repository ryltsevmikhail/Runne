import { describe, expect, it } from 'vitest'

import type { CanonicalWorkspace } from '@/entities/project'
import { createWorkspaceRefreshController } from './workspace-refresh'

const WORKSPACE_ID = '01890e00-0000-7000-8000-000000000002'
const WORKSPACE_A = '01890e00-0000-7000-8000-000000000010'
const projectFixture: CanonicalWorkspace = {
  projectId: '01890e00-0000-7000-8000-000000000001',
  workspaceId: WORKSPACE_ID,
  displayName: 'gocode-ui',
  version: 1,
  open: true,
}

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason: unknown) => void
  const promise = new Promise<T>((res, rej) => { resolve = res; reject = rej })
  return { promise, resolve, reject }
}

const emptyDiff = async () => ({ path: '', kind: 'modified' as const, hunks: [], truncated: false })

describe('workspace refresh controller', () => {
  it('keeps same workspace projection while a refresh is pending', async () => {
    const secondProject = deferred<CanonicalWorkspace>()
    const calls: string[] = []
    let projectCalls = 0
    const controller = createWorkspaceRefreshController({
      loadProject: async () => {
        projectCalls += 1
        return projectCalls === 1 ? projectFixture : secondProject.promise
      },
      loadFiles: async id => { calls.push(`files:${id}`); return { items: [] } },
      loadChanges: async id => { calls.push(`changes:${id}`); return { items: [] } },
      loadDiff: emptyDiff,
    })

    await controller.load(WORKSPACE_ID)
    const firstProjection = controller.project.value
    const refresh = controller.load(WORKSPACE_ID)
    expect(controller.project.value).toBe(firstProjection)
    secondProject.resolve(projectFixture)
    await refresh
    expect(controller.project.value).toBe(projectFixture)
    expect(calls).toEqual([
      `files:${WORKSPACE_ID}`,
      `changes:${WORKSPACE_ID}`,
      `files:${WORKSPACE_ID}`,
      `changes:${WORKSPACE_ID}`,
    ])
  })

  it('drops an old completion after invalidate and never invokes a new workspace loader', async () => {
    const old = deferred<CanonicalWorkspace>()
    let filesCalls = 0
    let changesCalls = 0
    const controller = createWorkspaceRefreshController({
      loadProject: async () => old.promise,
      loadFiles: async () => { filesCalls += 1; return { items: [] as const } },
      loadChanges: async () => { changesCalls += 1; return { items: [] as const } },
      loadDiff: emptyDiff,
    })
    const pending = controller.load(WORKSPACE_A)
    controller.invalidate()
    old.resolve({ ...projectFixture, workspaceId: WORKSPACE_A })
    await pending
    expect(controller.project.value).toBeNull()
    expect(filesCalls).toBe(0)
    expect(changesCalls).toBe(0)
  })
})
