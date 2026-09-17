import { ref, shallowRef, type Ref } from 'vue'

import type { WorkspaceChangeEntry, WorkspaceDiff } from '@/entities/diff'
import type { CanonicalWorkspace } from '@/entities/project'
import { isCanonicalRuntimeId } from '@/entities/project'
import type { WorkspaceFileEntry } from '@/entities/file-tree'

export interface WorkspaceRefreshLoaders {
  loadProject(id: string): Promise<CanonicalWorkspace>
  loadFiles(id: string, path: string, limit: number): Promise<{
    readonly items: readonly WorkspaceFileEntry[]
  }>
  loadChanges(id: string, limit: number): Promise<{
    readonly items: readonly WorkspaceChangeEntry[]
  }>
  loadDiff(id: string, path: string): Promise<WorkspaceDiff>
}

export interface WorkspaceRefreshController {
  readonly project: Ref<CanonicalWorkspace | null>
  readonly files: Ref<readonly WorkspaceFileEntry[]>
  readonly filesLoading: Ref<boolean>
  readonly filesError: Ref<boolean>
  readonly changes: Ref<readonly WorkspaceChangeEntry[]>
  readonly changesLoading: Ref<boolean>
  readonly changesError: Ref<boolean>
  readonly selectedPath: Ref<string | null>
  readonly selectedDiff: Ref<WorkspaceDiff | null>
  readonly diffLoading: Ref<boolean>
  readonly diffError: Ref<boolean>
  readonly loading: Ref<boolean>
  readonly error: Ref<boolean>
  load(workspaceId: string): Promise<void>
  selectChange(workspaceId: string, path: string): Promise<void>
  invalidate(): void
  markUnavailable(): void
  dispose(): void
}

type RefreshToken = Readonly<{ workspaceId: string; generation: number }>

export function createWorkspaceRefreshController(
  loaders: WorkspaceRefreshLoaders,
): WorkspaceRefreshController {
  const project = shallowRef<CanonicalWorkspace | null>(null)
  const files = shallowRef<readonly WorkspaceFileEntry[]>([])
  const filesLoading = ref(false)
  const filesError = ref(false)
  const changes = shallowRef<readonly WorkspaceChangeEntry[]>([])
  const changesLoading = ref(false)
  const changesError = ref(false)
  const selectedPath = ref<string | null>(null)
  const selectedDiff = shallowRef<WorkspaceDiff | null>(null)
  const diffLoading = ref(false)
  const diffError = ref(false)
  const loading = ref(false)
  const error = ref(false)
  let mounted = true
  let generation = 0
  let activeWorkspaceId = ''
  let diffGeneration = 0

  const current = (token: RefreshToken): boolean => mounted
    && token.generation === generation
    && token.workspaceId === activeWorkspaceId

  async function load(workspaceId: string): Promise<void> {
    activeWorkspaceId = workspaceId
    generation += 1
    const token = Object.freeze({ workspaceId, generation })
    error.value = false
    loading.value = true
    // Until this cycle's listing actually succeeds, the explorer must not
    // present the previous/default snapshot as a truthful "no files" state.
    filesError.value = true
    filesLoading.value = false
    changesLoading.value = false
    diffLoading.value = false
    diffGeneration += 1
    if (!isCanonicalRuntimeId(workspaceId)) {
      if (current(token)) {
        error.value = true
        loading.value = false
      }
      return
    }
    try {
      const nextProject = await loaders.loadProject(workspaceId)
      if (!current(token)) return
      project.value = nextProject
      await refreshFiles(token)
      if (!current(token)) return
      await refreshChanges(token)
    }
    catch {
      if (current(token)) error.value = true
    }
    finally {
      if (current(token)) loading.value = false
    }
  }

  async function refreshFiles(token: RefreshToken): Promise<void> {
    if (!current(token)) return
    filesLoading.value = true
    filesError.value = false
    try {
      const next = await loaders.loadFiles(token.workspaceId, '', 50)
      if (current(token)) files.value = next.items
    }
    catch {
      if (current(token)) {
        files.value = []
        filesError.value = true
      }
    }
    finally {
      if (current(token)) filesLoading.value = false
    }
  }

  async function refreshChanges(token: RefreshToken): Promise<void> {
    if (!current(token)) return
    diffGeneration += 1
    diffLoading.value = false
    changesLoading.value = true
    changesError.value = false
    try {
      const next = await loaders.loadChanges(token.workspaceId, 50)
      if (!current(token)) return
      changes.value = next.items
      const nextPath = changes.value[0]?.path ?? null
      selectedPath.value = nextPath
      if (nextPath !== null) await fetchDiff(token, nextPath)
      else if (current(token)) selectedDiff.value = null
    }
    catch {
      if (current(token)) {
        changes.value = []
        selectedPath.value = null
        selectedDiff.value = null
        changesError.value = true
      }
    }
    finally {
      if (current(token)) changesLoading.value = false
    }
  }

  async function fetchDiff(token: RefreshToken, path: string): Promise<void> {
    if (!current(token)) return
    const request = ++diffGeneration
    diffLoading.value = true
    diffError.value = false
    try {
      const next = await loaders.loadDiff(token.workspaceId, path)
      if (current(token) && request === diffGeneration && selectedPath.value === path) {
        selectedDiff.value = next
      }
    }
    catch {
      if (current(token) && request === diffGeneration && selectedPath.value === path) {
        selectedDiff.value = null
        diffError.value = true
      }
    }
    finally {
      if (current(token) && request === diffGeneration) diffLoading.value = false
    }
  }

  async function selectChange(workspaceId: string, path: string): Promise<void> {
    if (workspaceId !== activeWorkspaceId) return
    const token = Object.freeze({ workspaceId, generation })
    if (!current(token)) return
    selectedPath.value = path
    await fetchDiff(token, path)
  }

  function invalidate(): void {
    generation += 1
    activeWorkspaceId = ''
    diffGeneration += 1
    project.value = null
    files.value = []
    changes.value = []
    selectedPath.value = null
    selectedDiff.value = null
    filesLoading.value = false
    filesError.value = false
    changesLoading.value = false
    changesError.value = false
    diffLoading.value = false
    diffError.value = false
    loading.value = false
    error.value = false
  }

  function markUnavailable(): void {
    generation += 1
    diffGeneration += 1
    loading.value = false
    filesLoading.value = false
    changesLoading.value = false
    diffLoading.value = false
    error.value = true
  }

  function dispose(): void {
    mounted = false
    generation += 1
    activeWorkspaceId = ''
    diffGeneration += 1
  }

  return {
    project,
    files,
    filesLoading,
    filesError,
    changes,
    changesLoading,
    changesError,
    selectedPath,
    selectedDiff,
    diffLoading,
    diffError,
    loading,
    error,
    load,
    selectChange,
    invalidate,
    markUnavailable,
    dispose,
  }
}
