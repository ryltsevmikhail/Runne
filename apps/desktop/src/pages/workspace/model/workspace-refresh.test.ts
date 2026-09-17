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
const changeFixture = { path: 'src/main.ts', kind: 'modified' as const, additions: 1, deletions: 0 }
const diffFixture = { path: 'src/main.ts', kind: 'modified' as const, hunks: [], truncated: false }

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

  it('clears superseded diff loading when the next same-id load has no changes', async () => {
    const oldDiff = deferred<typeof diffFixture>()
    const diffStarted = deferred<undefined>()
    let changesCalls = 0
    const controller = createWorkspaceRefreshController({
      loadProject: async () => projectFixture,
      loadFiles: async () => ({ items: [] as const }),
      loadChanges: async () => ({ items: ++changesCalls === 1 ? [changeFixture] : [] }),
      loadDiff: async () => {
        diffStarted.resolve(undefined)
        return oldDiff.promise
      },
    })
    const firstLoad = controller.load(WORKSPACE_ID)
    await diffStarted.promise
    expect(controller.diffLoading.value).toBe(true)
    const secondLoad = controller.load(WORKSPACE_ID)
    await secondLoad
    expect(controller.changes.value).toEqual([])
    expect(controller.selectedPath.value).toBeNull()
    expect(controller.selectedDiff.value).toBeNull()
    expect(controller.diffLoading.value).toBe(false)
    oldDiff.resolve(diffFixture)
    await firstLoad
    expect(controller.selectedDiff.value).toBeNull()
  })

  it.each(['empty', 'error'] as const)(
    'clears diff loading after a same-id refresh invalidates a user diff (%s)',
    async outcome => {
      const oldDiff = deferred<typeof diffFixture>()
      const diffStarted = deferred<undefined>()
      const changesStarted = deferred<undefined>()
      const refreshedChanges = deferred<{ readonly items: readonly [] }>()
      const secondProject = deferred<CanonicalWorkspace>()
      let changesCalls = 0
      let diffCalls = 0
      let projectCalls = 0
      const controller = createWorkspaceRefreshController({
        loadProject: async () => {
          if (++projectCalls === 1) return projectFixture
          return secondProject.promise
        },
        loadFiles: async () => ({ items: [] as const }),
        loadChanges: async () => {
          if (++changesCalls === 1) return { items: [changeFixture] }
          changesStarted.resolve(undefined)
          const next = await refreshedChanges.promise
          if (outcome === 'error') throw new Error('changes unavailable')
          return next
        },
        loadDiff: async () => {
          if (++diffCalls === 1) return diffFixture
          diffStarted.resolve(undefined)
          return oldDiff.promise
        },
      })

      await controller.load(WORKSPACE_ID)
      expect(controller.changes.value).toEqual([changeFixture])
      expect(controller.selectedDiff.value).toBe(diffFixture)

      const refresh = controller.load(WORKSPACE_ID)
      expect(controller.changes.value).toEqual([changeFixture])
      expect(controller.selectedPath.value).toBe(changeFixture.path)
      expect(controller.selectedDiff.value).toBe(diffFixture)
      const selection = controller.selectChange(WORKSPACE_ID, changeFixture.path)
      await diffStarted.promise
      expect(controller.diffLoading.value).toBe(true)
      secondProject.resolve(projectFixture)
      await changesStarted.promise

      if (outcome === 'error') refreshedChanges.reject(new Error('refresh failed'))
      else refreshedChanges.resolve({ items: [] })
      await refresh
      oldDiff.resolve(diffFixture)
      await selection

      expect(controller.changes.value).toEqual([])
      expect(controller.selectedPath.value).toBeNull()
      expect(controller.selectedDiff.value).toBeNull()
      expect(controller.diffLoading.value).toBe(false)
    },
  )

  it('clears superseded files loading when the next same-id project load fails', async () => {
    const oldFiles = deferred<{ readonly items: readonly [] }>()
    const filesStarted = deferred<undefined>()
    let projectCalls = 0
    const controller = createWorkspaceRefreshController({
      loadProject: async () => {
        if (++projectCalls === 1) return projectFixture
        throw new Error('project unavailable')
      },
      loadFiles: async () => {
        filesStarted.resolve(undefined)
        return oldFiles.promise
      },
      loadChanges: async () => ({ items: [] as const }),
      loadDiff: emptyDiff,
    })
    const firstLoad = controller.load(WORKSPACE_ID)
    await filesStarted.promise
    expect(controller.filesLoading.value).toBe(true)
    const secondLoad = controller.load(WORKSPACE_ID)
    await secondLoad
    expect(controller.project.value).toBe(projectFixture)
    expect(controller.error.value).toBe(true)
    expect(controller.filesLoading.value).toBe(false)
    oldFiles.resolve({ items: [] })
    await firstLoad
  })

  it('clears superseded changes loading when the next same-id project load fails', async () => {
    const oldChanges = deferred<{ readonly items: readonly [] }>()
    const changesStarted = deferred<undefined>()
    let projectCalls = 0
    const controller = createWorkspaceRefreshController({
      loadProject: async () => {
        if (++projectCalls === 1) return projectFixture
        throw new Error('project unavailable')
      },
      loadFiles: async () => ({ items: [] as const }),
      loadChanges: async () => {
        changesStarted.resolve(undefined)
        return oldChanges.promise
      },
      loadDiff: emptyDiff,
    })
    const firstLoad = controller.load(WORKSPACE_ID)
    await changesStarted.promise
    expect(controller.changesLoading.value).toBe(true)
    const secondLoad = controller.load(WORKSPACE_ID)
    await secondLoad
    expect(controller.project.value).toBe(projectFixture)
    expect(controller.error.value).toBe(true)
    expect(controller.changesLoading.value).toBe(false)
    oldChanges.resolve({ items: [] })
    await firstLoad
  })

  it('never presents an unloaded file explorer as an empty success', async () => {
    const controller = createWorkspaceRefreshController({
      loadProject: async () => {
        throw new Error('project unavailable')
      },
      loadFiles: async () => ({ items: [] }),
      loadChanges: async () => ({ items: [] as const }),
      loadDiff: emptyDiff,
    })
    await controller.load(WORKSPACE_ID)
    expect(controller.error.value).toBe(true)
    // A cycle that never reached a listing must render "unavailable", never
    // the truthful-looking "no files" state (live finding F5).
    expect(controller.filesError.value).toBe(true)
  })
})
