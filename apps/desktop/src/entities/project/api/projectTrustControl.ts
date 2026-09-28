import { invoke as tauriInvoke } from '@tauri-apps/api/core'
import { reactive } from 'vue'
import { isCanonicalRuntimeId } from './projects'

export type ProjectTrustAction = 'confirm_project' | 'revoke_project'
export interface ProjectTrustControlSnapshot {
  readonly projectId: string
  readonly projectName: string
  readonly projectVersion: string
  readonly workspaceId: string
  readonly workspaceName: string
  readonly workspaceVersion: string
  readonly status: 'untrusted' | 'trusted' | 'managed'
  readonly managedDenyMask: number
  readonly provenance: 'default' | 'user' | 'managed'
  readonly epoch: string
  readonly revision: string
  readonly rootAdmissionVersion: string | null
}
export interface ProjectTrustControlResult {
  readonly outcome: 'cancelled' | 'updated'
  readonly snapshot: ProjectTrustControlSnapshot | null
}
type Invoke = (command: string, args?: Record<string, unknown>) => Promise<unknown>

const projectTrustRevisions = reactive<Record<string, number>>({})

export function projectTrustRevision(projectId: string): number {
  return projectTrustRevisions[projectId] ?? 0
}

export function markProjectTrustChanged(projectId: string): void {
  projectTrustRevisions[projectId] = projectTrustRevision(projectId) + 1
}

export async function getProjectTrustControl(
  projectId: string,
  workspaceId: string,
  invoke: Invoke = tauriInvoke,
): Promise<ProjectTrustControlSnapshot> {
  const value = await invoke('get_project_trust_control', { projectId, workspaceId })
  if (!isSnapshot(value) || value.projectId !== projectId || value.workspaceId !== workspaceId) {
    throw new Error('Invalid Project Trust response')
  }
  return value
}

export async function requestProjectTrustControl(
  projectId: string,
  workspaceId: string,
  action: ProjectTrustAction,
  invoke: Invoke = tauriInvoke,
): Promise<ProjectTrustControlResult> {
  const value = await invoke('request_project_trust_control', { projectId, workspaceId, action })
  if (!record(value) || Object.keys(value).length !== 2
    || (value.outcome !== 'cancelled' && value.outcome !== 'updated')) {
    throw new Error('Invalid Project Trust command response')
  }
  if (value.outcome === 'cancelled' && value.snapshot === null) return { outcome: 'cancelled', snapshot: null }
  if (value.outcome === 'updated' && isSnapshot(value.snapshot)
    && value.snapshot.projectId === projectId && value.snapshot.workspaceId === workspaceId) {
    return { outcome: 'updated', snapshot: value.snapshot }
  }
  throw new Error('Invalid Project Trust command result')
}

function isSnapshot(value: unknown): value is ProjectTrustControlSnapshot {
  if (!record(value) || Object.keys(value).length !== 12) return false
  const item = value
  const decimal = (candidate: unknown, positive = false) => typeof candidate === 'string'
    && /^(0|[1-9]\d*)$/.test(candidate) && BigInt(candidate) <= 0xffff_ffff_ffff_ffffn
    && (!positive || candidate !== '0')
  const name = (candidate: unknown) => typeof candidate === 'string' && candidate.length > 0
    && new TextEncoder().encode(candidate).length <= 256 && !/[\p{Cc}\p{Cf}]/u.test(candidate)
  const status = item.status === 'untrusted' || item.status === 'trusted' || item.status === 'managed'
  const provenance = item.provenance === 'default' || item.provenance === 'user' || item.provenance === 'managed'
  const maskValid = typeof item.managedDenyMask === 'number' && Number.isInteger(item.managedDenyMask)
    && item.managedDenyMask >= 0 && item.managedDenyMask <= 0xffff_ffff
  const root = item.rootAdmissionVersion === null
    || (typeof item.rootAdmissionVersion === 'string' && decimal(item.rootAdmissionVersion, true))
  const rootWithinWorkspace = root && (item.rootAdmissionVersion === null
    || (typeof item.rootAdmissionVersion === 'string' && typeof item.workspaceVersion === 'string'
      && decimal(item.workspaceVersion, true) && BigInt(item.rootAdmissionVersion) <= BigInt(item.workspaceVersion)))
  const trustProvenance = item.provenance === 'managed'
    ? item.status === 'managed' || (typeof item.managedDenyMask === 'number' && item.managedDenyMask !== 0)
    : item.provenance === 'default'
      ? item.status === 'untrusted' && item.revision === '0' && item.managedDenyMask === 0
      : item.status !== 'managed' && item.revision !== '0' && item.managedDenyMask === 0
  return isCanonicalRuntimeId(item.projectId) && name(item.projectName)
    && decimal(item.projectVersion, true) && isCanonicalRuntimeId(item.workspaceId)
    && name(item.workspaceName) && decimal(item.workspaceVersion, true)
    && status && maskValid && provenance && decimal(item.epoch, true)
    && decimal(item.revision) && root && rootWithinWorkspace
    && trustProvenance
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}
