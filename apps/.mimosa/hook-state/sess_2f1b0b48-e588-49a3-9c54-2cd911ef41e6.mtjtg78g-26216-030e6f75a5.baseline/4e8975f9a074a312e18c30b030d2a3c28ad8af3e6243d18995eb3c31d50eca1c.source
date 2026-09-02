import type {
  ConversationChannelErrorCode,
  ConversationRecoveryState,
} from './types'

export const canonicalUuidV7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
export const maximumMessageBytes = 64 * 1024
export const recoveryStates: readonly ConversationRecoveryState[] = [
  'live',
  'reconnecting',
  'incompatible',
  'revoked',
  'resync_required',
  'fatal',
]
export const channelErrorCodes: readonly ConversationChannelErrorCode[] = [
  'conversation_subscription_unavailable',
  'runtime_incompatible',
  'runtime_revoked',
  'replay_resync_required',
  'runtime_identity_conflict',
  'local_projection_unavailable',
]
