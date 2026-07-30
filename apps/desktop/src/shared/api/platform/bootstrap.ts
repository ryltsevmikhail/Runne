import { invoke as tauriInvoke } from '@tauri-apps/api/core'

export interface BootstrapState {
  readonly theme: 'dark' | 'light'
  readonly runtimeMode: RuntimeMode
  readonly runtime: RuntimeConnectionState
}

export type RuntimeMode = 'external_local' | 'bundled'

const runtimeModes: readonly RuntimeMode[] = ['external_local', 'bundled']

export function isRuntimeMode(value: unknown): value is RuntimeMode {
  return typeof value === 'string' && runtimeModes.includes(value as RuntimeMode)
}

export type RuntimeConnectionState =
  | 'unconfigured'
  | 'profile_loaded'
  | 'peer_verified'
  | 'bootstrap_proved'
  | 'authenticated'
  | 'reconciling'
  | 'live'
  | 'reconnecting'
  | 'incompatible'
  | 'revoked'
  | 'resync_required'
  | 'fatal'

const runtimeConnectionStates: readonly RuntimeConnectionState[] = [
  'unconfigured',
  'profile_loaded',
  'peer_verified',
  'bootstrap_proved',
  'authenticated',
  'reconciling',
  'live',
  'reconnecting',
  'incompatible',
  'revoked',
  'resync_required',
  'fatal',
]

export function isRuntimeConnectionState(value: unknown): value is RuntimeConnectionState {
  return typeof value === 'string'
    && runtimeConnectionStates.includes(value as RuntimeConnectionState)
}

type Invoke = (command: string, args?: Record<string, unknown>) => Promise<unknown>

export async function loadBootstrap(invoke: Invoke = tauriInvoke): Promise<BootstrapState> {
  const value = await invoke('get_bootstrap')
  if (!isBootstrapState(value)) {
    throw new Error('Invalid bootstrap response')
  }
  return value
}

export async function saveTheme(
  theme: BootstrapState['theme'],
  invoke: Invoke = tauriInvoke,
): Promise<void> {
  await invoke('set_theme', { theme })
}

export async function connectRuntime(
  invoke: Invoke = tauriInvoke,
): Promise<RuntimeConnectionState> {
  const value = await invoke('connect_runtime')
  if (!isRuntimeConnectionState(value)) {
    throw new Error('Invalid runtime connection response')
  }
  return value
}

function isBootstrapState(value: unknown): value is BootstrapState {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false
  }
  const record = value as Record<string, unknown>
  return (
    Object.keys(record).length === 3
    && (record.theme === 'dark' || record.theme === 'light')
    && isRuntimeMode(record.runtimeMode)
    && isRuntimeConnectionState(record.runtime)
  )
}
