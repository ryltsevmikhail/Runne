import { invoke as tauriInvoke } from '@tauri-apps/api/core'

type Invoke = (command: string, args?: Record<string, unknown>) => Promise<unknown>

/** One installed local model, metadata-only (never paths). */
export interface LocalModelInstalled {
  readonly manifestDigest: string
  readonly modelId: string
  readonly modelRevision: string
  readonly matrixRevision: string
  readonly activeRefs: number
}

/** One staged (not yet admitted) candidate. */
export interface LocalModelCandidate {
  readonly candidateId: string
  readonly manifestDigest: string
  readonly modelId: string
  readonly modelRevision: string
  readonly license: string
  readonly artifactDigest: string
  readonly byteLen: number
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0
}

function parseInstalled(value: unknown): LocalModelInstalled | null {
  if (typeof value !== 'object' || value === null) return null
  const v = value as Record<string, unknown>
  if (!isNonEmptyString(v.manifestDigest) || !isNonEmptyString(v.modelId)) return null
  if (!isNonEmptyString(v.modelRevision) || typeof v.activeRefs !== 'number') return null
  return {
    manifestDigest: v.manifestDigest,
    modelId: v.modelId,
    modelRevision: v.modelRevision,
    matrixRevision: typeof v.matrixRevision === 'string' ? v.matrixRevision : '',
    activeRefs: v.activeRefs,
  }
}

function parseCandidate(value: unknown): LocalModelCandidate | null {
  if (typeof value !== 'object' || value === null) return null
  const v = value as Record<string, unknown>
  for (const key of [
    'candidateId',
    'manifestDigest',
    'modelId',
    'modelRevision',
    'license',
    'artifactDigest',
  ]) {
    if (!isNonEmptyString(v[key])) return null
  }
  if (typeof v.byteLen !== 'number') return null
  return {
    candidateId: v.candidateId as string,
    manifestDigest: v.manifestDigest as string,
    modelId: v.modelId as string,
    modelRevision: v.modelRevision as string,
    license: v.license as string,
    artifactDigest: v.artifactDigest as string,
    byteLen: v.byteLen as number,
  }
}

/** Lists installed local models (metadata-only). */
export async function listLocalModels(invoke: Invoke = tauriInvoke): Promise<LocalModelInstalled[]> {
  const value = await invoke('local_model_list')
  if (!Array.isArray(value)) throw new Error('Invalid local model list')
  return value.map(parseInstalled).filter((m): m is LocalModelInstalled => m !== null)
}

/** Admits a staged candidate after the owner accepted the license. */
export async function admitLocalModel(
  candidateId: string,
  licenseDigest: string,
  invoke: Invoke = tauriInvoke,
): Promise<LocalModelInstalled> {
  const value = await invoke('local_model_admit', { candidateId, licenseDigest })
  const installed = parseInstalled(value)
  if (installed === null) throw new Error('Invalid installed model')
  return installed
}

/** Discards a staged (not yet admitted) candidate. */
export async function discardLocalModel(
  candidateId: string,
  invoke: Invoke = tauriInvoke,
): Promise<boolean> {
  const value = await invoke('local_model_discard', { candidateId })
  return value === true
}
