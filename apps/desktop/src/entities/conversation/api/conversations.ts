import { Channel, invoke as tauriInvoke } from '@tauri-apps/api/core'

import {
  createConversationTimeline,
  reduceConversationTimeline,
  setConversationRecovery,
} from '../model/timeline'
import type {
  ConversationMessage,
  ConversationRecoveryState,
  ConversationSnapshot,
  ConversationTimeline,
  ConversationTimelineUpdate,
} from '../model/timeline'

type Invoke = (command: string, args?: Record<string, unknown>) => Promise<unknown>
export type ConversationTimelineListener = (snapshot: ConversationSnapshot) => void
export type ConversationUnsubscribe = () => Promise<void>
export interface ConversationSession {
  readonly sendMessage: (text: string) => Promise<ConversationSnapshot>
  readonly resync: () => Promise<ConversationSnapshot>
  readonly unsubscribe: ConversationUnsubscribe
}

export type ConversationChannelErrorCode =
  | 'conversation_subscription_unavailable'
  | 'runtime_incompatible'
  | 'runtime_revoked'
  | 'replay_resync_required'
  | 'runtime_identity_conflict'
  | 'local_projection_unavailable'

export interface ConversationChannelError {
  readonly kind: 'error'
  readonly code: ConversationChannelErrorCode
}

export type ConversationChannelEvent =
  | ConversationTimelineUpdate
  | ConversationChannelError

const canonicalUuidV7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const maximumMessageBytes = 64 * 1024
const recoveryStates: readonly ConversationRecoveryState[] = [
  'live',
  'reconnecting',
  'incompatible',
  'revoked',
  'resync_required',
  'fatal',
]
const channelErrorCodes: readonly ConversationChannelErrorCode[] = [
  'conversation_subscription_unavailable',
  'runtime_incompatible',
  'runtime_revoked',
  'replay_resync_required',
  'runtime_identity_conflict',
  'local_projection_unavailable',
]

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

export async function subscribeProjectConversation(
  projectId: number,
  initialSnapshot: ConversationSnapshot,
  onTimeline: ConversationTimelineListener,
  invoke: Invoke = tauriInvoke,
): Promise<ConversationSession> {
  validateProjectId(projectId)
  const sanitizedInitial = parseConversationSnapshot(initialSnapshot)
  if (sanitizedInitial === null) {
    throw new Error('Invalid conversation response')
  }

  let timeline = createConversationTimeline(sanitizedInitial)
  let activeSubscriptionId: string | null = null
  let resyncedSnapshot: ConversationSnapshot | null = null
  let generation = 0
  let closed = false
  let processing = Promise.resolve()

  const serialize = <T>(operation: () => Promise<T>): Promise<T> => {
    const result = processing.then(operation)
    processing = result.then(
      () => undefined,
      () => undefined,
    )
    return result
  }

  const publishRecovery = (recovery: ConversationRecoveryState): void => {
    timeline = setConversationRecovery(timeline, recovery)
    onTimeline(timeline.snapshot)
  }
  const currentRecovery = (): ConversationRecoveryState => timeline.snapshot.recovery

  const cancelActive = async (): Promise<void> => {
    generation += 1
    const subscriptionId = activeSubscriptionId
    activeSubscriptionId = null
    if (subscriptionId === null) {
      return
    }
    try {
      await invoke('cancel_conversation_subscription', { subscriptionId })
    }
    catch {
      // Cancellation is best effort after a terminal or already-closed channel.
    }
  }

  const terminate = async (recovery: ConversationRecoveryState): Promise<void> => {
    publishRecovery(recovery)
    await cancelActive()
  }

  const startSubscription = async (): Promise<void> => {
    if (closed) {
      return
    }
    const currentGeneration = generation + 1
    generation = currentGeneration
    const pending: unknown[] = []
    let ready = false
    const channel = new Channel<unknown>((value) => {
      if (!ready) {
        pending.push(value)
        return
      }
      void serialize(() => handleEvent(value, currentGeneration))
    })
    const value = await invoke('subscribe_project_conversation', {
      projectId,
      onUpdate: channel,
    })
    if (!isCanonicalId(value)) {
      await terminate('incompatible')
      throw new Error('Invalid conversation subscription response')
    }
    if (closed || generation !== currentGeneration) {
      try {
        await invoke('cancel_conversation_subscription', { subscriptionId: value })
      }
      catch {
        // A concurrently closed subscription may already be absent natively.
      }
      return
    }
    activeSubscriptionId = value
    ready = true
    for (const pendingValue of pending) {
      void serialize(() => handleEvent(pendingValue, currentGeneration))
    }
  }

  const reconcileAndResubscribe = async (): Promise<void> => {
    await cancelActive()
    if (closed) {
      return
    }
    const snapshot = await openProjectConversation(projectId, invoke)
    if (closed) {
      return
    }
    if (
      snapshot.conversationId !== timeline.snapshot.conversationId
      || snapshot.projectionRevision < timeline.snapshot.projectionRevision
    ) {
      await terminate('incompatible')
      return
    }
    const reconciledTimeline = createConversationTimeline(snapshot)
    await startSubscription()
    if (closed) {
      return
    }
    timeline = reconciledTimeline
    onTimeline(timeline.snapshot)
  }

  const handleEvent = async (
    value: unknown,
    eventGeneration: number,
  ): Promise<void> => {
    if (closed || eventGeneration !== generation) {
      return
    }
    const event = parseConversationChannelEvent(value)
    if (event === null) {
      await terminate('incompatible')
      return
    }
    if (event.kind === 'error') {
      await terminate(recoveryForError(event.code))
      return
    }

    const reduction = reduceConversationTimeline(timeline, event)
    if (reduction.kind === 'gap') {
      try {
        await reconcileAndResubscribe()
      }
      catch {
        if (!closed) {
          publishRecovery('fatal')
        }
      }
      return
    }
    if (reduction.kind === 'incompatible') {
      await terminate('incompatible')
      return
    }

    timeline = reduction.timeline
    if (reduction.kind === 'applied') {
      onTimeline(timeline.snapshot)
    }

    const subscriptionId = activeSubscriptionId
    if (
      closed
      || eventGeneration !== generation
      || subscriptionId === null
    ) {
      return
    }
    try {
      await invoke('ack_conversation_update', {
        subscriptionId,
        projectionRevision: event.projectionRevision,
      })
    }
    catch {
      if (!closed) {
        await terminate('reconnecting')
      }
    }
  }

  await startSubscription()

  const unsubscribe: ConversationUnsubscribe = async () => {
    if (closed) {
      return
    }
    closed = true
    await cancelActive()
  }

  const sendMessage = (text: string): Promise<ConversationSnapshot> => serialize(async () => {
    if (closed) {
      throw new Error('Conversation subscription is closed')
    }
    const snapshot = await sendProjectMessage(projectId, text, invoke)
    if (closed) {
      throw new Error('Conversation subscription is closed')
    }
    const current = timeline.snapshot
    if (
      snapshot.conversationId !== current.conversationId
      || snapshot.projectionRevision < current.projectionRevision
      || snapshot.streamVersion < current.streamVersion
      || (
        snapshot.projectionRevision === current.projectionRevision
        && !sameSnapshot(snapshot, current)
      )
    ) {
      await terminate('incompatible')
      throw new Error('Incompatible conversation response')
    }
    if (snapshot.projectionRevision === current.projectionRevision) {
      return current
    }
    timeline = createConversationTimeline(snapshot)
    onTimeline(timeline.snapshot)
    return timeline.snapshot
  })

  const resync = (): Promise<ConversationSnapshot> => serialize(async () => {
    if (closed) {
      throw new Error('Conversation subscription is closed')
    }
    if (currentRecovery() !== 'resync_required') {
      throw new Error('Conversation resync is not required')
    }
    publishRecovery('reconnecting')
    try {
      await cancelActive()
      if (closed) {
        throw new Error('Conversation subscription is closed')
      }
      let snapshot = resyncedSnapshot
      if (snapshot === null) {
        snapshot = await resyncProjectConversation(projectId, invoke)
        if (
          snapshot.conversationId !== timeline.snapshot.conversationId
          || snapshot.recovery !== 'live'
        ) {
          await terminate('incompatible')
          throw new Error('Incompatible conversation resync response')
        }
        resyncedSnapshot = snapshot
      }
      const reconciledTimeline = createConversationTimeline(snapshot)
      await startSubscription()
      if (closed) {
        throw new Error('Conversation subscription is closed')
      }
      timeline = reconciledTimeline
      resyncedSnapshot = null
      onTimeline(timeline.snapshot)
    }
    catch (error) {
      if (!closed && currentRecovery() === 'reconnecting') {
        publishRecovery('resync_required')
      }
      throw error
    }
    if (currentRecovery() !== 'live') {
      throw new Error('Conversation resync failed safely')
    }
    return timeline.snapshot
  })

  return {
    sendMessage,
    resync,
    unsubscribe,
  }
}

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

function validateProjectId(projectId: number): void {
  if (!Number.isSafeInteger(projectId) || projectId <= 0) {
    throw new Error('Invalid project identity')
  }
}

function parseConversationSnapshot(value: unknown): ConversationSnapshot | null {
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

function sameSnapshot(
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

function recoveryForError(code: ConversationChannelErrorCode): ConversationRecoveryState {
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

export type {
  ConversationMessage,
  ConversationRecoveryState,
  ConversationSnapshot,
  ConversationTimeline,
  ConversationTimelineUpdate,
}
