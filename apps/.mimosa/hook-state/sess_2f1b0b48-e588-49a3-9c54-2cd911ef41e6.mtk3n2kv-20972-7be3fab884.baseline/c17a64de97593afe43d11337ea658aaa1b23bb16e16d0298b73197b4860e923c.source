import { invoke as tauriInvoke } from '@tauri-apps/api/core'

export interface NotificationSyncSnapshot {
  readonly shown: number
  readonly pending: number
}

type Invoke = (command: string, args?: Record<string, unknown>) => Promise<unknown>

export async function syncNotifications(invoke: Invoke = tauriInvoke): Promise<NotificationSyncSnapshot> {
  const value = await invoke('sync_notifications')
  if (!isRecord(value) || Object.keys(value).length !== 2 || !Object.hasOwn(value, 'shown') || !Object.hasOwn(value, 'pending')) {
    throw new Error('Invalid notification response')
  }
  if (!boundedCount(value.shown) || !boundedCount(value.pending)) throw new Error('Invalid notification counts')
  return { shown: value.shown, pending: value.pending }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function boundedCount(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= 128
}
