import { invoke as tauriInvoke } from '@tauri-apps/api/core'

export interface ConversationMessage {
  readonly messageId: string
  readonly role: 'user' | 'assistant'
  readonly taskRunId: string
  readonly attemptId: string
  readonly text: string
  readonly committedAt: number
}

export interface ConversationSnapshot {
  readonly conversationId: string
  readonly streamVersion: number
  readonly messages: readonly ConversationMessage[]
}

type Invoke = (command: string, args?: Record<string, unknown>) => Promise<unknown>

const canonicalUuidV7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const maximumMessageBytes = 64 * 1024

export async function openProjectConversation(
  projectId: number,
  invoke: Invoke = tauriInvoke,
): Promise<ConversationSnapshot> {
  validateProjectId(projectId)
  const value = await invoke('open_project_conversation', { projectId })
  if (!isConversationSnapshot(value)) {
    throw new Error('Invalid conversation response')
  }
  return value
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
  if (!isConversationSnapshot(value)) {
    throw new Error('Invalid conversation response')
  }
  return value
}

function validateProjectId(projectId: number): void {
  if (!Number.isSafeInteger(projectId) || projectId <= 0) {
    throw new Error('Invalid project identity')
  }
}

function isConversationSnapshot(value: unknown): value is ConversationSnapshot {
  if (!isExactRecord(value, ['conversationId', 'streamVersion', 'messages'])) {
    return false
  }
  return (
    isCanonicalId(value.conversationId)
    && isNonNegativeInteger(value.streamVersion)
    && Array.isArray(value.messages)
    && value.messages.every(isConversationMessage)
  )
}

function isConversationMessage(value: unknown): value is ConversationMessage {
  if (
    !isExactRecord(value, [
      'messageId',
      'role',
      'taskRunId',
      'attemptId',
      'text',
      'committedAt',
    ])
  ) {
    return false
  }
  return (
    isCanonicalId(value.messageId)
    && (value.role === 'user' || value.role === 'assistant')
    && isCanonicalId(value.taskRunId)
    && isCanonicalId(value.attemptId)
    && typeof value.text === 'string'
    && value.text.length > 0
    && new TextEncoder().encode(value.text).length <= maximumMessageBytes
    && isNonNegativeInteger(value.committedAt)
  )
}

function isCanonicalId(value: unknown): value is string {
  return typeof value === 'string' && canonicalUuidV7.test(value)
}

function isNonNegativeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0
}

function isExactRecord<const K extends string>(
  value: unknown,
  keys: readonly K[],
): value is Record<K, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false
  }
  const actualKeys = Object.keys(value)
  return actualKeys.length === keys.length && keys.every(key => actualKeys.includes(key))
}
