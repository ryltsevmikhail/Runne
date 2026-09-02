import { invoke as tauriInvoke } from '@tauri-apps/api/core'

export type UpdateState =
  | 'unavailable'
  | 'available'
  | 'staged'
  | 'restart_required'
  | 'health_check'
  | 'committed'
  | 'rolled_back'

export interface UpdateStatusSnapshot {
  readonly state: UpdateState
  readonly currentVersion: string
  readonly availableVersion: string | null
  readonly artifactSha256: string | null
  readonly reason: string | null
}

type Invoke = (command: string, args?: Record<string, unknown>) => Promise<unknown>

export async function getUpdateStatus(
  invoke: Invoke = tauriInvoke,
): Promise<UpdateStatusSnapshot> {
  const value = await invoke('get_update_status')
  if (!isUpdateStatus(value)) throw new Error('Invalid update status')
  return value
}

export async function checkUpdate(
  invoke: Invoke = tauriInvoke,
): Promise<UpdateStatusSnapshot> {
  return updateCommand('check_update', invoke)
}

export async function downloadUpdate(
  invoke: Invoke = tauriInvoke,
): Promise<UpdateStatusSnapshot> {
  return updateCommand('download_update', invoke)
}

export async function prepareUpdateInstall(
  confirmActiveTaskRuns: boolean,
  invoke: Invoke = tauriInvoke,
): Promise<UpdateStatusSnapshot> {
  return updateCommand('prepare_update_install', invoke, { confirmActiveTaskRuns })
}

async function updateCommand(
  command: string,
  invoke: Invoke,
  args?: Record<string, unknown>,
): Promise<UpdateStatusSnapshot> {
  const value = await invoke(command, args)
  if (!isUpdateStatus(value)) throw new Error('Invalid update status')
  return value
}

function isUpdateStatus(value: unknown): value is UpdateStatusSnapshot {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false
  const candidate = value as Record<string, unknown>
  const keys = ['state', 'currentVersion', 'availableVersion', 'artifactSha256', 'reason']
  if (Object.keys(candidate).length !== keys.length || keys.some(key => !(key in candidate))) return false
  return isUpdateState(candidate.state)
    && typeof candidate.currentVersion === 'string'
    && optionalString(candidate.availableVersion)
    && (candidate.artifactSha256 === null || /^[0-9a-f]{64}$/.test(String(candidate.artifactSha256)))
    && optionalString(candidate.reason)
}

function isUpdateState(value: unknown): value is UpdateState {
  return value === 'unavailable'
    || value === 'available'
    || value === 'staged'
    || value === 'restart_required'
    || value === 'health_check'
    || value === 'committed'
    || value === 'rolled_back'
}

function optionalString(value: unknown): value is string | null {
  return value === null || typeof value === 'string'
}
