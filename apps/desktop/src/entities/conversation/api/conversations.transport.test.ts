import { describe, expect, it, vi } from 'vitest'

import {
  openProjectConversation,
  parseConversationChannelEvent,
  sendProjectMessage,
} from './conversations'
import { snapshot, update } from './conversations.test-support'

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
  it('loads a strict sanitized timeline for one local project', async () => {
    const calls: Array<[string, Record<string, unknown> | undefined]> = []

    const value = await openProjectConversation(7, async (command, args) => {
      calls.push([command, args])
      return snapshot
    })

    expect(value).toEqual(snapshot)
    expect(calls).toEqual([['open_project_conversation', { projectId: 7 }]])
  })

  it('sends only project identity and bounded text through typed IPC', async () => {
    const calls: Array<[string, Record<string, unknown> | undefined]> = []

    const value = await sendProjectMessage(7, 'hello', async (command, args) => {
      calls.push([command, args])
      return snapshot
    })

    expect(value.messages.at(1)?.text).toBe('Runne local response: hello')
    expect(calls).toEqual([
      ['send_project_message', { projectId: 7, text: 'hello' }],
    ])
  })

  it('rejects unknown fields, roles, and malformed canonical identities', async () => {
    await expect(
      openProjectConversation(7, async () => ({
        ...snapshot,
        token: 'must-not-cross-ipc',
      })),
    ).rejects.toThrow('Invalid conversation response')

    await expect(
      openProjectConversation(7, async () => ({
        ...snapshot,
        messages: [{ ...snapshot.messages[0], role: 'tool' }],
      })),
    ).rejects.toThrow('Invalid conversation response')

    await expect(
      openProjectConversation(7, async () => ({
        ...snapshot,
        conversationId: 'not-a-uuid',
      })),
    ).rejects.toThrow('Invalid conversation response')

    await expect(
      openProjectConversation(7, async () => ({
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
