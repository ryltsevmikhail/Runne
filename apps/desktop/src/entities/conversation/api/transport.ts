import { invoke as tauriInvoke } from '@tauri-apps/api/core'

import type {
  ConversationSnapshot,
  Invoke,
} from './types'
import { maximumMessageBytes } from './constants'
import {
  parseConversationSnapshot,
  validateProjectId,
} from './validation'

export async function openProjectConversation(
  projectId: number,
  invoke: Invoke = tauriInvoke,
): Promise<ConversationSnapshot> {
  validateProjectId(projectId)
  const value = await invoke('open_project_conversation', { projectId })
  const snapshot = parseConversationSnapshot(value)
  if (snapshot === null) {
    throw new Error('Invalid conversation response')
  }
  return snapshot
}

export async function resyncProjectConversation(
  projectId: number,
  invoke: Invoke = tauriInvoke,
): Promise<ConversationSnapshot> {
  validateProjectId(projectId)
  const value = await invoke('resync_project_conversation', { projectId })
  const snapshot = parseConversationSnapshot(value)
  if (snapshot === null) {
    throw new Error('Invalid conversation resync response')
  }
  return snapshot
}

export async function sendProjectMessage(
  projectId: number,
  text: string,
  invoke: Invoke = tauriInvoke,
): Promise<ConversationSnapshot> {
  validateProjectId(projectId)
  if (text.length === 0 || new TextEncoder().encode(text).length > maximumMessageBytes) {
    throw new Error('Invalid conversation message')
  }
  const value = await invoke('send_project_message', { projectId, text })
  const snapshot = parseConversationSnapshot(value)
  if (snapshot === null) {
    throw new Error('Invalid conversation response')
  }
  return snapshot
}
