import { invoke as tauriInvoke } from '@tauri-apps/api/core'

export interface DiagnosticsExportPreview {
  readonly schemaVersion: 1
  readonly redactionVersion: 1
  readonly categories: readonly string[]
  readonly estimatedBytes: number
}

export interface DiagnosticsExportResult {
  readonly status: 'saved' | 'cancelled'
}

type Invoke = (command: string) => Promise<unknown>

export async function getDiagnosticsExportPreview(
  invoke: Invoke = tauriInvoke,
): Promise<DiagnosticsExportPreview> {
  const value = await invoke('get_diagnostics_export_preview')
  if (!isPreview(value)) throw new Error('Invalid diagnostics export preview')
  return value
}

export async function exportDiagnostics(
  invoke: Invoke = tauriInvoke,
): Promise<DiagnosticsExportResult> {
  const value = await invoke('export_diagnostics')
  if (!isRecord(value) || (value.status !== 'saved' && value.status !== 'cancelled')) {
    throw new Error('Invalid diagnostics export result')
  }
  return { status: value.status }
}

function isPreview(value: unknown): value is DiagnosticsExportPreview {
  if (!isRecord(value) || value.schemaVersion !== 1 || value.redactionVersion !== 1) return false
  const estimatedBytes = value.estimatedBytes
  return Array.isArray(value.categories)
    && value.categories.every(category => typeof category === 'string' && category.length > 0)
    && typeof estimatedBytes === 'number'
    && Number.isSafeInteger(estimatedBytes)
    && estimatedBytes >= 0
    && estimatedBytes <= 131_072
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}
