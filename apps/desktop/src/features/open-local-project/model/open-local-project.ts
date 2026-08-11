import {
  acquireRendererGeneration,
  prepareSelectedWorkspace,
  requestDirectorySelection,
  type DirectorySelection,
  type PreparedWorkspace,
  type WorkspacePreparation,
} from '@/entities/project'

type AcquireGeneration = () => Promise<number>
type SelectDirectory = (requestId: string, rendererGeneration: number) => Promise<DirectorySelection | null>
type PrepareWorkspace = (request: WorkspacePreparation) => Promise<PreparedWorkspace>

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
