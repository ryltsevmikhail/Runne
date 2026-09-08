import type {
  ConversationMessage,
  ConversationRecoveryState,
  ConversationSnapshot,
  ConversationTimeline,
  ConversationTimelineUpdate,
} from '../model/timeline'

export type {
  ConversationMessage,
  ConversationRecoveryState,
  ConversationSnapshot,
  ConversationTimeline,
  ConversationTimelineUpdate,
}

export type Invoke = (command: string, args?: Record<string, unknown>) => Promise<unknown>
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
