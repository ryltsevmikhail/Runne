import { invoke as tauriInvoke } from '@tauri-apps/api/core'

export interface BootstrapState {
  readonly theme: 'dark' | 'light'
  readonly runtime: 'contract_pending'
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

function isBootstrapState(value: unknown): value is BootstrapState {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false
  }
  const record = value as Record<string, unknown>
  return (
    Object.keys(record).length === 2
    && (record.theme === 'dark' || record.theme === 'light')
    && record.runtime === 'contract_pending'
  )
}
