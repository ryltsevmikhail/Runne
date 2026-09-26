import {
  openTextOnlyConversation,
  openWorkspaceConversation,
  resyncTextOnlyConversation,
  resyncWorkspaceConversation,
  sendTextOnlyMessage,
  sendWorkspaceMessage,
} from './transport'
import type { Invoke } from './types'

export function openConversationForOwner(
  textOnly: boolean,
  workspaceId: string,
  invoke: Invoke,
) {
  return textOnly
    ? openTextOnlyConversation(invoke)
    : openWorkspaceConversation(workspaceId, invoke)
}

export function resyncConversationForOwner(
  textOnly: boolean,
  workspaceId: string,
  invoke: Invoke,
) {
  return textOnly
    ? resyncTextOnlyConversation(invoke)
    : resyncWorkspaceConversation(workspaceId, invoke)
}

export function sendMessageForOwner(textOnly: boolean, workspaceId: string, text: string, invoke: Invoke) {
  return textOnly
    ? sendTextOnlyMessage(text, invoke)
    : sendWorkspaceMessage(workspaceId, text, invoke)
}

export function subscribeForOwner(
  textOnly: boolean,
  workspaceId: string,
  onUpdate: unknown,
  invoke: Invoke,
) {
  const command = textOnly ? 'subscribe_text_only_conversation' : 'subscribe_workspace_conversation'
  const args = textOnly ? { onUpdate } : { workspaceId, onUpdate }
  return invoke(command, args)
}
