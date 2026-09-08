import { invoke as tauriInvoke } from '@tauri-apps/api/core'

export interface ShortcutBindings {
  readonly commandPalette: string
  readonly openProject: string
}

type Invoke = (command: string, args?: Record<string, unknown>) => Promise<unknown>

export async function loadShortcuts(invoke: Invoke = tauriInvoke): Promise<ShortcutBindings> {
  const value = await invoke('get_shortcuts')
  if (!isShortcutBindings(value)) throw new Error('Invalid shortcuts response')
  return value
}

export async function saveShortcuts(
  shortcuts: ShortcutBindings,
  invoke: Invoke = tauriInvoke,
): Promise<ShortcutBindings> {
  if (!isShortcutBindings(shortcuts)) throw new Error('Invalid shortcuts')
  const value = await invoke('set_shortcuts', { shortcuts })
  if (!isShortcutBindings(value) || value.commandPalette !== shortcuts.commandPalette || value.openProject !== shortcuts.openProject) {
    throw new Error('Invalid shortcuts acknowledgement')
  }
  return value
}

export function isShortcutBindings(value: unknown): value is ShortcutBindings {
  if (!isRecord(value)) return false
  const commandPalette = value.commandPalette
  const openProject = value.openProject
  return typeof commandPalette === 'string'
    && typeof openProject === 'string'
    && commandPalette !== openProject
    && validBinding(commandPalette)
    && validBinding(openProject)
}

function validBinding(binding: string): boolean {
  const parts = binding.split('+')
  const modifiers = parts.slice(0, -1)
  return parts.length >= 2
    && parts.length <= 4
    && modifiers.every(part => ['Ctrl', 'Alt', 'Shift', 'Meta'].includes(part))
    && new Set(modifiers).size === modifiers.length
    && /^[A-Za-z0-9]$|^F\d{1,2}$/.test(parts.at(-1) ?? '')
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}
