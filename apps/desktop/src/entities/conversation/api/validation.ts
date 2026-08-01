import {
  canonicalUuidV7,
  channelErrorCodes,
  maximumMessageBytes,
  recoveryStates,
} from './constants'
import type {
  ConversationChannelErrorCode,
  ConversationChannelEvent,
  ConversationMessage,
  ConversationRecoveryState,
  ConversationSnapshot,
} from './types'

export function parseConversationChannelEvent(
  value: unknown,
): ConversationChannelEvent | null {
  if (isExactRecord(value, ['kind', 'code'])) {
    if (
      value.kind !== 'error'
      || !isChannelErrorCode(value.code)
    ) {
      return null
    }
    return {
      kind: 'error',
      code: value.code,
    }
  }

  if (!isExactRecord(value, [
    'kind',
    'conversationId',
    'projectionRevision',
    'streamVersion',
    'message',
    'recovery',
  ])) {
    return null
  }
  if (
    value.kind !== 'update'
    || !isCanonicalId(value.conversationId)
    || !isNonNegativeInteger(value.projectionRevision)
    || !isNonNegativeInteger(value.streamVersion)
    || (value.message !== null && !isConversationMessage(value.message))
    || !isRecoveryState(value.recovery)
  ) {
    return null
  }
  return {
    kind: 'update',
    conversationId: value.conversationId,
    projectionRevision: value.projectionRevision,
    streamVersion: value.streamVersion,
    message: value.message === null ? null : copyMessage(value.message),
    recovery: value.recovery,
  }
}

export function validateProjectId(projectId: number): void {
  if (!Number.isSafeInteger(projectId) || projectId <= 0) {
    throw new Error('Invalid project identity')
  }
}

export function parseConversationSnapshot(value: unknown): ConversationSnapshot | null {
  if (!isExactRecord(value, [
    'conversationId',
    'projectionRevision',
    'streamVersion',
    'messages',
    'recovery',
  ])) {
    return null
  }
  if (
    !isCanonicalId(value.conversationId)
    || !isNonNegativeInteger(value.projectionRevision)
    || !isNonNegativeInteger(value.streamVersion)
    || !Array.isArray(value.messages)
    || !value.messages.every(isConversationMessage)
    || !hasUniqueMessageIds(value.messages)
    || !isRecoveryState(value.recovery)
  ) {
    return null
  }
  return {
    conversationId: value.conversationId,
    projectionRevision: value.projectionRevision,
    streamVersion: value.streamVersion,
    messages: value.messages.map(copyMessage),
    recovery: value.recovery,
  }
}

function hasUniqueMessageIds(messages: readonly ConversationMessage[]): boolean {
  const ids = new Set(messages.map(message => message.messageId))
  return ids.size === messages.length
}

function copyMessage(message: ConversationMessage): ConversationMessage {
  return {
    messageId: message.messageId,
    role: message.role,
    taskRunId: message.taskRunId,
    attemptId: message.attemptId,
    text: message.text,
    committedAt: message.committedAt,
  }
}

export function sameSnapshot(
  left: ConversationSnapshot,
  right: ConversationSnapshot,
): boolean {
  return (
    left.conversationId === right.conversationId
    && left.projectionRevision === right.projectionRevision
    && left.streamVersion === right.streamVersion
    && left.recovery === right.recovery
    && left.messages.length === right.messages.length
    && left.messages.every((message, index) => {
      const candidate = right.messages[index]
      return candidate !== undefined && sameMessage(message, candidate)
    })
  )
}

function sameMessage(
  left: ConversationMessage,
  right: ConversationMessage,
): boolean {
  return (
    left.messageId === right.messageId
    && left.role === right.role
    && left.taskRunId === right.taskRunId
    && left.attemptId === right.attemptId
    && left.text === right.text
    && left.committedAt === right.committedAt
  )
}

function isRecoveryState(value: unknown): value is ConversationRecoveryState {
  return typeof value === 'string'
    && recoveryStates.includes(value as ConversationRecoveryState)
}

function isChannelErrorCode(value: unknown): value is ConversationChannelErrorCode {
  return typeof value === 'string'
    && channelErrorCodes.includes(value as ConversationChannelErrorCode)
}

export function recoveryForError(code: ConversationChannelErrorCode): ConversationRecoveryState {
  switch (code) {
    case 'conversation_subscription_unavailable':
      return 'reconnecting'
    case 'runtime_incompatible':
      return 'incompatible'
    case 'runtime_revoked':
      return 'revoked'
    case 'replay_resync_required':
      return 'resync_required'
    case 'runtime_identity_conflict':
    case 'local_projection_unavailable':
      return 'fatal'
  }
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

export function isCanonicalId(value: unknown): value is string {
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
