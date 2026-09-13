import {
  acquireRendererGeneration,
  createCanonicalProject,
  createCanonicalWorkspace,
  openSelectedWorkspace,
  retryOpenSelectedWorkspace,
  prepareSelectedWorkspace,
  requestDirectorySelection,
  type DirectorySelection,
  type PreparedWorkspace,
  type WorkspacePreparation,
} from '@/entities/project'

type AcquireGeneration = () => Promise<number>
type SelectDirectory = (requestId: string, rendererGeneration: number) => Promise<DirectorySelection | null>
type PrepareWorkspace = (request: WorkspacePreparation) => Promise<PreparedWorkspace>
type CreateProject = (displayName: string) => Promise<{ projectId: string; newVersion: number }>
type CreateWorkspace = (projectId: string, displayName: string) => Promise<{ workspaceId: string; newVersion: number }>
type OpenWorkspace = (request: { prepared: string; rendererGeneration: number; requestId: string }) => Promise<void>

export interface LocalProjectOpenResult {
  readonly projectId: string
  readonly workspaceId: string
}

export class LocalProjectOpenError extends Error {
  constructor(readonly stage: 'selection' | 'creation' | 'workspace') {
    super('Local project could not be opened')
  }
}

async function atStage<T>(stage: LocalProjectOpenError['stage'], operation: () => Promise<T>): Promise<T> {
  try { return await operation() }
  catch { throw new LocalProjectOpenError(stage) }
}

let rendererGeneration: number | null = null

async function currentRendererGeneration(acquire: AcquireGeneration): Promise<number> {
  rendererGeneration ??= await acquire()
  return rendererGeneration
}

export async function selectAndOpenLocalProject(
  acquire: AcquireGeneration = acquireRendererGeneration,
  select: SelectDirectory = requestDirectorySelection,
): Promise<DirectorySelection | null> {
  const generation = await currentRendererGeneration(acquire)
  return select(crypto.randomUUID(), generation)
}

export async function selectAndPrepareLocalProject(
  workspaceId: string,
  expectedVersion: number,
  acquire: AcquireGeneration = acquireRendererGeneration,
  select: SelectDirectory = requestDirectorySelection,
  prepare: PrepareWorkspace = prepareSelectedWorkspace,
): Promise<PreparedWorkspace | null> {
  const generation = await currentRendererGeneration(acquire)
  const requestId = crypto.randomUUID()
  const selection = await select(requestId, generation)
  if (selection === null) {
    return null
  }
  return prepare({
    selection: selection.reference,
    rendererGeneration: generation,
    requestId,
    workspaceId,
    expectedVersion,
  })
}

export interface WorkspaceOpenAttemptBinding {
  readonly workspaceId: string
  readonly prepared: string
  readonly requestId: string
  readonly rendererGeneration: number
}

export class RetryableWorkspaceOpen extends Error {
  readonly binding: WorkspaceOpenAttemptBinding
  readonly #retry: () => Promise<PreparedWorkspace>

  constructor(binding: WorkspaceOpenAttemptBinding, retry: () => Promise<PreparedWorkspace>) {
    super('Workspace connection can be retried')
    this.binding = Object.freeze({ ...binding })
    this.#retry = retry
  }

  retry(): Promise<PreparedWorkspace> { return this.#retry() }
}

async function dispatchExistingWorkspace(
  binding: WorkspaceOpenAttemptBinding,
  prepared: PreparedWorkspace,
  dispatch: OpenWorkspace,
  retry: OpenWorkspace,
): Promise<PreparedWorkspace> {
  try {
    await dispatch({
      prepared: binding.prepared,
      rendererGeneration: binding.rendererGeneration,
      requestId: binding.requestId,
    })
    return prepared
  }
  catch (error) {
    if (typeof error === 'object' && error !== null && 'code' in error
      && error.code === 'prepared_workspace_retryable') {
      throw new RetryableWorkspaceOpen(
        binding,
        () => dispatchExistingWorkspace(binding, prepared, retry, retry),
      )
    }
    throw new LocalProjectOpenError('workspace')
  }
}

export async function selectAndOpenExistingWorkspace(
  workspaceId: string,
  expectedVersion: number,
  acquire: AcquireGeneration = acquireRendererGeneration,
  select: SelectDirectory = requestDirectorySelection,
  prepare: PrepareWorkspace = prepareSelectedWorkspace,
  open: OpenWorkspace = openSelectedWorkspace,
  retry: OpenWorkspace = retryOpenSelectedWorkspace,
): Promise<PreparedWorkspace | null> {
  const generation = await atStage('selection', () => currentRendererGeneration(acquire))
  const requestId = crypto.randomUUID()
  const selection = await atStage('selection', () => select(requestId, generation))
  if (selection === null) return null
  const prepared = await atStage('workspace', () => prepare({
    selection: selection.reference, rendererGeneration: generation, requestId,
    workspaceId, expectedVersion,
  }))
  const binding: WorkspaceOpenAttemptBinding = Object.freeze({
    workspaceId,
    prepared: prepared.reference, rendererGeneration: generation, requestId,
  })
  return dispatchExistingWorkspace(binding, prepared, open, retry)
}

export async function selectAndCreateLocalProject(
  acquire: AcquireGeneration = acquireRendererGeneration,
  select: SelectDirectory = requestDirectorySelection,
  createProject: CreateProject = createCanonicalProject,
  createWorkspace: CreateWorkspace = createCanonicalWorkspace,
  prepare: PrepareWorkspace = prepareSelectedWorkspace,
  open: OpenWorkspace = openSelectedWorkspace,
): Promise<LocalProjectOpenResult | null> {
  const generation = await atStage('selection', () => currentRendererGeneration(acquire))
  const requestId = crypto.randomUUID()
  const selection = await atStage('selection', () => select(requestId, generation))
  if (selection === null) {
    return null
  }
  const displayName = 'Selected folder'
  const project = await atStage('creation', () => createProject(displayName))
  const workspace = await atStage('creation', () => createWorkspace(project.projectId, displayName))
  const prepared = await atStage('workspace', () => prepare({
    selection: selection.reference,
    rendererGeneration: generation,
    requestId,
    workspaceId: workspace.workspaceId,
    expectedVersion: workspace.newVersion,
  }))
  await atStage('workspace', () => open({
    prepared: prepared.reference,
    rendererGeneration: generation,
    requestId,
  }))
  return { projectId: project.projectId, workspaceId: workspace.workspaceId }
}
