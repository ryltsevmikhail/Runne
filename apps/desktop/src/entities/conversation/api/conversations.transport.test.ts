import { describe, expect, it, vi } from 'vitest'

import {
  openTextOnlyConversation,
  openWorkspaceConversation,
  parseConversationChannelEvent,
  subscribeTextOnlyConversation,
  sendWorkspaceMessage,
} from './conversations'
import { snapshot, update, workspaceId } from './conversations.test-support'

vi.mock('@tauri-apps/api/core', () => ({
  Channel: class {
    onmessage: (value: unknown) => void

    constructor(onmessage: (value: unknown) => void) {
      this.onmessage = onmessage
    }
  },
  invoke: vi.fn(),
}))

describe('conversation IPC transport validation', () => {
  it('opens the dedicated text-only owner without a workspace or conversation ID', async () => {
    const calls: Array<[string, Record<string, unknown> | undefined]> = []

    const value = await openTextOnlyConversation(async (command, args) => {
      calls.push([command, args])
      return snapshot
    })

    expect(value).toEqual(snapshot)
    expect(calls).toEqual([['open_text_only_conversation', undefined]])
  })

  it('subscribes and sends through TextOnly IPC without workspace identity', async () => {
    const calls: Array<[string, Record<string, unknown> | undefined]> = []
    const session = await subscribeTextOnlyConversation(snapshot, () => {}, async (command, args) => {
      calls.push([command, args])
      if (command === 'subscribe_text_only_conversation') {
        return '018f2e3a-7000-7000-8000-000000000201'
      }
      return snapshot
    })

    await session.sendMessage('hello')
    await session.unsubscribe()

    expect(calls.map(([command, args]) => [command, args && Object.keys(args)])).toEqual([
      ['subscribe_text_only_conversation', ['onUpdate']],
      ['send_text_only_message', ['text']],
      ['cancel_conversation_subscription', ['subscriptionId']],
    ])
  })

  it('loads a strict sanitized timeline for one canonical workspace', async () => {
    const calls: Array<[string, Record<string, unknown> | undefined]> = []

    const value = await openWorkspaceConversation(workspaceId, async (command, args) => {
      calls.push([command, args])
      return snapshot
    })

    expect(value).toEqual(snapshot)
    expect(calls).toEqual([['open_workspace_conversation', { workspaceId }]])
  })

  it('sends only workspace identity and bounded text through typed IPC', async () => {
    const calls: Array<[string, Record<string, unknown> | undefined]> = []

    const value = await sendWorkspaceMessage(workspaceId, 'hello', async (command, args) => {
      calls.push([command, args])
      return snapshot
    })

    expect(value.messages.at(1)?.text).toBe('Runne local response: hello')
    expect(calls).toEqual([
      ['send_workspace_message', { workspaceId, text: 'hello' }],
    ])
  })

  it('rejects unknown fields, roles, and malformed canonical identities', async () => {
    await expect(
      openWorkspaceConversation(workspaceId, async () => ({
        ...snapshot,
        token: 'must-not-cross-ipc',
      })),
    ).rejects.toThrow('Invalid conversation response')

    await expect(
      openWorkspaceConversation(workspaceId, async () => ({
        ...snapshot,
        messages: [{ ...snapshot.messages[0], role: 'tool' }],
      })),
    ).rejects.toThrow('Invalid conversation response')

    await expect(
      openWorkspaceConversation(workspaceId, async () => ({
        ...snapshot,
        conversationId: 'not-a-uuid',
      })),
    ).rejects.toThrow('Invalid conversation response')

    await expect(
      openWorkspaceConversation(workspaceId, async () => ({
        ...snapshot,
        messages: [snapshot.messages[0], snapshot.messages[0]],
      })),
    ).rejects.toThrow('Invalid conversation response')
  })

  it('validates exact channel keys, UUIDv7 identities, bounds, and recovery states', () => {
    expect(parseConversationChannelEvent(update)).toEqual(update)
    expect(parseConversationChannelEvent({
      kind: 'error',
      code: 'runtime_revoked',
    })).toEqual({
      kind: 'error',
      code: 'runtime_revoked',
    })

    expect(parseConversationChannelEvent({ ...update, token: 'must-not-cross' })).toBeNull()
    expect(parseConversationChannelEvent({
      ...update,
      conversationId: '018f2e3a-7000-6000-8000-000000000101',
    })).toBeNull()
    expect(parseConversationChannelEvent({
      ...update,
      projectionRevision: Number.MAX_SAFE_INTEGER + 1,
    })).toBeNull()
    expect(parseConversationChannelEvent({
      ...update,
      recovery: 'retrying',
    })).toBeNull()
    expect(parseConversationChannelEvent({
      kind: 'error',
      code: 'runtime_retrying',
    })).toBeNull()
  })
})
