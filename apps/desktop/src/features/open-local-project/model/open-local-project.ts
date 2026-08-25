import {
  acquireRendererGeneration,
  createCanonicalProject,
  createCanonicalWorkspace,
  openSelectedWorkspace,
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

export async function selectAndCreateLocalProject(
  acquire: AcquireGeneration = acquireRendererGeneration,
  select: SelectDirectory = requestDirectorySelection,
  createProject: CreateProject = createCanonicalProject,
  createWorkspace: CreateWorkspace = createCanonicalWorkspace,
  prepare: PrepareWorkspace = prepareSelectedWorkspace,
  open: OpenWorkspace = openSelectedWorkspace,
): Promise<LocalProjectOpenResult | null> {
  const generation = await currentRendererGeneration(acquire)
  const requestId = crypto.randomUUID()
  const selection = await select(requestId, generation)
  if (selection === null) {
    return null
  }
  const displayName = 'Selected folder'
  const project = await createProject(displayName)
  const workspace = await createWorkspace(project.projectId, displayName)
  const prepared = await prepare({
    selection: selection.reference,
    rendererGeneration: generation,
    requestId,
    workspaceId: workspace.workspaceId,
    expectedVersion: workspace.newVersion,
  })
  await open({
    prepared: prepared.reference,
    rendererGeneration: generation,
    requestId,
  })
  return { projectId: project.projectId, workspaceId: workspace.workspaceId }
}
