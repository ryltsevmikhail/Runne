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

const deviceSnapshotKeys = [
  'connection',
  'authenticated',
  'runtimeVersion',
  'launchGeneration',
] as const

export async function getDeviceStatus(invoke: Invoke = tauriInvoke): Promise<RuntimeDeviceSnapshot> {
  const value = await invoke('get_device_status')
  const snapshot = parseDeviceSnapshot(value)
  if (snapshot === null) throw new Error('Invalid device status')
  return snapshot
}

function parseDeviceSnapshot(value: unknown): RuntimeDeviceSnapshot | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) return null
  const keys = Reflect.ownKeys(value)
  if (keys.length !== deviceSnapshotKeys.length || deviceSnapshotKeys.some(key => !Object.hasOwn(value, key))) {
    return null
  }
  const candidate = value as Record<string, unknown>
  const version = candidate.runtimeVersion
  const generation = candidate.launchGeneration
  if (!isRuntimeConnectionState(candidate.connection)
    || typeof candidate.authenticated !== 'boolean'
    || (version !== null && typeof version !== 'string')
    || (generation !== null && (typeof generation !== 'number' || !Number.isSafeInteger(generation) || generation < 0))) {
    return null
  }
  return {
    connection: candidate.connection,
    authenticated: candidate.authenticated,
    runtimeVersion: version,
    launchGeneration: generation,
  }
}
