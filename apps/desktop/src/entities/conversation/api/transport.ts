import { invoke as tauriInvoke } from '@tauri-apps/api/core'

import type {
  ConversationSnapshot,
  Invoke,
} from './types'
import { maximumMessageBytes } from './constants'
import {
  parseConversationSnapshot,
  validateWorkspaceId,
} from './validation'

export async function openWorkspaceConversation(
  workspaceId: string,
  invoke: Invoke = tauriInvoke,
): Promise<ConversationSnapshot> {
  validateWorkspaceId(workspaceId)
  const value = await invoke('open_workspace_conversation', { workspaceId })
  const snapshot = parseConversationSnapshot(value)
  if (snapshot === null) {
    throw new Error('Invalid conversation response')
  }
  return snapshot
}

export async function resyncWorkspaceConversation(
  workspaceId: string,
  invoke: Invoke = tauriInvoke,
): Promise<ConversationSnapshot> {
  validateWorkspaceId(workspaceId)
  const value = await invoke('resync_workspace_conversation', { workspaceId })
  const snapshot = parseConversationSnapshot(value)
  if (snapshot === null) {
    throw new Error('Invalid conversation resync response')
  }
  return snapshot
}

export async function sendWorkspaceMessage(
  workspaceId: string,
  text: string,
  invoke: Invoke = tauriInvoke,
): Promise<ConversationSnapshot> {
  validateWorkspaceId(workspaceId)
  if (text.length === 0 || new TextEncoder().encode(text).length > maximumMessageBytes) {
    throw new Error('Invalid conversation message')
  }
  const value = await invoke('send_workspace_message', { workspaceId, text })
  const snapshot = parseConversationSnapshot(value)
  if (snapshot === null) {
    throw new Error('Invalid conversation response')
  }
  return snapshot
}

export async function openTextOnlyConversation(
  invoke: Invoke = tauriInvoke,
): Promise<ConversationSnapshot> {
  const value = await invoke('open_text_only_conversation')
  const snapshot = parseConversationSnapshot(value)
  if (snapshot === null) throw new Error('Invalid conversation response')
  return snapshot
}

export async function resyncTextOnlyConversation(
  invoke: Invoke = tauriInvoke,
): Promise<ConversationSnapshot> {
  const value = await invoke('resync_text_only_conversation')
  const snapshot = parseConversationSnapshot(value)
  if (snapshot === null) throw new Error('Invalid conversation response')
  return snapshot
}

export async function sendTextOnlyMessage(
  text: string,
  invoke: Invoke = tauriInvoke,
): Promise<ConversationSnapshot> {
  if (text.length === 0 || new TextEncoder().encode(text).length > maximumMessageBytes) {
    throw new Error('Invalid conversation message')
  }
  const value = await invoke('send_text_only_message', { text })
  const snapshot = parseConversationSnapshot(value)
  if (snapshot === null) throw new Error('Invalid conversation response')
  return snapshot
}
