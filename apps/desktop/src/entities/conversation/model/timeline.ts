export type ConversationRecoveryState =
  | 'live'
  | 'reconnecting'
  | 'incompatible'
  | 'revoked'
  | 'resync_required'
  | 'fatal'

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
  readonly projectionRevision: number
  readonly streamVersion: number
  readonly messages: readonly ConversationMessage[]
  readonly recovery: ConversationRecoveryState
}

export interface ConversationTimelineUpdate {
  readonly kind: 'update'
  readonly conversationId: string
  readonly projectionRevision: number
  readonly streamVersion: number
  readonly message: ConversationMessage | null
  readonly recovery: ConversationRecoveryState
}

export interface ConversationTimeline {
  readonly snapshot: ConversationSnapshot
  readonly lastUpdateSignature: string | null
}

export type ConversationTimelineReduction =
  | {
    readonly kind: 'applied' | 'duplicate'
    readonly timeline: ConversationTimeline
  }
  | {
    readonly kind: 'gap' | 'incompatible'
    readonly timeline: ConversationTimeline
  }

export function createConversationTimeline(
  snapshot: ConversationSnapshot,
): ConversationTimeline {
  return {
    snapshot: {
      ...snapshot,
      messages: [...snapshot.messages],
    },
    lastUpdateSignature: null,
  }
}

export function reduceConversationTimeline(
  timeline: ConversationTimeline,
  update: ConversationTimelineUpdate,
): ConversationTimelineReduction {
  const current = timeline.snapshot
  if (update.conversationId !== current.conversationId) {
    return incompatible(timeline)
  }

  if (update.projectionRevision < current.projectionRevision) {
    return incompatible(timeline)
  }

  if (update.projectionRevision === current.projectionRevision) {
    const signature = updateSignature(update)
    if (
      signature === timeline.lastUpdateSignature
      || (timeline.lastUpdateSignature === null && updateMatchesSnapshot(update, current))
    ) {
      return { kind: 'duplicate', timeline }
    }
    return incompatible(timeline)
  }

  if (update.projectionRevision !== current.projectionRevision + 1) {
    return { kind: 'gap', timeline }
  }

  if (update.streamVersion < current.streamVersion) {
    return incompatible(timeline)
  }

  const messages = [...current.messages]
  if (update.message !== null) {
    const existing = messages.find(message => message.messageId === update.message?.messageId)
    if (existing !== undefined) {
      if (!sameMessage(existing, update.message)) {
        return incompatible(timeline)
      }
    }
    else {
      messages.push(update.message)
    }
  }

  return {
    kind: 'applied',
    timeline: {
      snapshot: {
        conversationId: update.conversationId,
        projectionRevision: update.projectionRevision,
        streamVersion: update.streamVersion,
        messages,
        recovery: update.recovery,
      },
      lastUpdateSignature: updateSignature(update),
    },
  }
}

export function setConversationRecovery(
  timeline: ConversationTimeline,
  recovery: ConversationRecoveryState,
): ConversationTimeline {
  return {
    ...timeline,
    snapshot: {
      ...timeline.snapshot,
      recovery,
    },
  }
}

function incompatible(timeline: ConversationTimeline): ConversationTimelineReduction {
  return { kind: 'incompatible', timeline }
}

function updateMatchesSnapshot(
  update: ConversationTimelineUpdate,
  snapshot: ConversationSnapshot,
): boolean {
  if (
    update.streamVersion !== snapshot.streamVersion
    || update.recovery !== snapshot.recovery
  ) {
    return false
  }
  return update.message === null
    || snapshot.messages.some(message => sameMessage(message, update.message as ConversationMessage))
}

function updateSignature(update: ConversationTimelineUpdate): string {
  return JSON.stringify(update)
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
