export {
  openWorkspaceConversation,
  openTextOnlyConversation,
  resyncWorkspaceConversation,
  resyncTextOnlyConversation,
  sendWorkspaceMessage,
  sendTextOnlyMessage,
} from './transport'
import { invoke as tauriInvoke } from '@tauri-apps/api/core'
import { subscribeConversationForOwner } from './session'
import type { ConversationSession, ConversationSnapshot, ConversationTimelineListener, Invoke } from './types'

export function subscribeWorkspaceConversation(
  workspaceId: string,
  initialSnapshot: ConversationSnapshot,
  onTimeline: ConversationTimelineListener,
  invoke: Invoke = tauriInvoke,
): Promise<ConversationSession> {
  return subscribeConversationForOwner(false, workspaceId, initialSnapshot, onTimeline, invoke)
}

export function subscribeTextOnlyConversation(
  initialSnapshot: ConversationSnapshot,
  onTimeline: ConversationTimelineListener,
  invoke: Invoke = tauriInvoke,
): Promise<ConversationSession> {
  return subscribeConversationForOwner(true, '', initialSnapshot, onTimeline, invoke)
}
export { parseConversationChannelEvent } from './validation'
export type {
  ConversationChannelError,
  ConversationChannelErrorCode,
  ConversationChannelEvent,
  ConversationMessage,
  ConversationRecoveryState,
  ConversationSession,
  ConversationSnapshot,
  ConversationTimeline,
  ConversationTimelineListener,
  ConversationTimelineUpdate,
  ConversationUnsubscribe,
} from './types'
