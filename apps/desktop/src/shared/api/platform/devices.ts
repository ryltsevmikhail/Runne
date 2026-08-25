import { invoke as tauriInvoke } from '@tauri-apps/api/core'

import type { RuntimeConnectionState } from './bootstrap'
import { isRuntimeConnectionState } from './bootstrap'

export interface RuntimeDeviceSnapshot {
  readonly connection: RuntimeConnectionState
  readonly authenticated: boolean
  readonly runtimeVersion: string | null
  readonly launchGeneration: number | null
}

type Invoke = (command: string) => Promise<unknown>

export async function getDeviceStatus(invoke: Invoke = tauriInvoke): Promise<RuntimeDeviceSnapshot> {
  const value = await invoke('get_device_status')
  if (!isDeviceSnapshot(value)) throw new Error('Invalid device status')
  return value
}

function isDeviceSnapshot(value: unknown): value is RuntimeDeviceSnapshot {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false
  const candidate = value as Record<string, unknown>
  const version = candidate.runtimeVersion
  const generation = candidate.launchGeneration
  return isRuntimeConnectionState(candidate.connection)
    && typeof candidate.authenticated === 'boolean'
    && (version === null || typeof version === 'string')
    && (generation === null || (typeof generation === 'number' && Number.isSafeInteger(generation) && generation >= 0))
}
