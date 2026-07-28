import { invoke as tauriInvoke } from '@tauri-apps/api/core'
import { isRuntimeConnectionState } from './bootstrap'
import type { RuntimeConnectionState } from './bootstrap'

export interface DiagnosticsSnapshot {
  readonly appVersion: string
  readonly platform: string
  readonly databaseSchemaVersion: number
  readonly databaseGeneration: number
  readonly projectCount: number
  readonly runtime: RuntimeConnectionState
}

type Invoke = (command: string, args?: Record<string, unknown>) => Promise<unknown>

export async function getDiagnostics(
  invoke: Invoke = tauriInvoke,
): Promise<DiagnosticsSnapshot> {
  const value = await invoke('get_diagnostics')
  if (!isDiagnosticsSnapshot(value)) {
    throw new Error('Invalid diagnostics response')
  }
  return value
}

function isDiagnosticsSnapshot(value: unknown): value is DiagnosticsSnapshot {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false
  }
  const record = value as Record<string, unknown>
  return (
    Object.keys(record).length === 6
    && typeof record.appVersion === 'string'
    && typeof record.platform === 'string'
    && Number.isSafeInteger(record.databaseSchemaVersion)
    && Number.isSafeInteger(record.databaseGeneration)
    && Number.isSafeInteger(record.projectCount)
    && isRuntimeConnectionState(record.runtime)
  )
}
