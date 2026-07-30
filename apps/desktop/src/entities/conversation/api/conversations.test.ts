import { describe, expect, it, vi } from 'vitest'

import {
  openProjectConversation,
  parseConversationChannelEvent,
  sendProjectMessage,
  subscribeProjectConversation,
} from './conversations'
import type { ConversationSnapshot } from './conversations'

vi.mock('@tauri-apps/api/core', () => ({
  Channel: class {
    onmessage: (value: unknown) => void

    constructor(onmessage: (value: unknown) => void) {
      this.onmessage = onmessage
    }
  },
  invoke: vi.fn(),
}))

const snapshot = {
  conversationId: '018f2e3a-7000-7000-8000-000000000101',
  projectionRevision: 3,
  streamVersion: 3,
  messages: [
    {
      messageId: '018f2e3a-7000-7000-8000-000000000102',
      role: 'user',
      taskRunId: '018f2e3a-7000-7000-8000-000000000103',
      attemptId: '018f2e3a-7000-7000-8000-000000000104',
      text: 'hello',
      committedAt: 1_753_800_000_001,
    },
    {
      messageId: '018f2e3a-7000-7000-8000-000000000105',
      role: 'assistant',
      taskRunId: '018f2e3a-7000-7000-8000-000000000103',
      attemptId: '018f2e3a-7000-7000-8000-000000000104',
      text: 'GOCODE local response: hello',
      committedAt: 1_753_800_000_002,
    },
  ],
  recovery: 'live',
} as const

const update = {
  kind: 'update',
  conversationId: snapshot.conversationId,
  projectionRevision: 4,
  streamVersion: 4,
  message: {
    messageId: '018f2e3a-7000-7000-8000-000000000106',
    role: 'assistant',
    taskRunId: '018f2e3a-7000-7000-8000-000000000103',
    attemptId: '018f2e3a-7000-7000-8000-000000000104',
    text: 'next',
    committedAt: 1_753_800_000_003,
  },
  recovery: 'live',
} as const

describe('conversation IPC adapter', () => {
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

    expect(value.messages.at(1)?.text).toBe('GOCODE local response: hello')
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

  it('publishes a validated update before acknowledging its exact revision', async () => {
    const order: string[] = []
    let onmessage: ((value: unknown) => void) | undefined
    const invoke = vi.fn(async (command: string, args?: Record<string, unknown>) => {
      if (command === 'subscribe_project_conversation') {
        onmessage = (args?.onUpdate as { onmessage: (value: unknown) => void }).onmessage
        return '018f2e3a-7000-7000-8000-000000000120'
      }
      if (command === 'ack_conversation_update') {
        order.push(`ack:${String(args?.projectionRevision)}`)
      }
    })

    const unsubscribe = await subscribeProjectConversation(
      7,
      snapshot,
      value => order.push(`render:${value.projectionRevision}`),
      invoke,
    )
    onmessage?.(update)
    await vi.waitFor(() => expect(order).toEqual(['render:4', 'ack:4']))

    await unsubscribe()
    expect(invoke).toHaveBeenLastCalledWith('cancel_conversation_subscription', {
      subscriptionId: '018f2e3a-7000-7000-8000-000000000120',
    })
  })

  it('cancels, reconciles, and creates a fresh subscription on a projection gap', async () => {
    const order: string[] = []
    const channels: Array<(value: unknown) => void> = []
    let subscriptions = 0
    const reconciled = {
      ...snapshot,
      projectionRevision: 5,
      streamVersion: 5,
    }
    const invoke = vi.fn(async (command: string, args?: Record<string, unknown>) => {
      order.push(command)
      if (command === 'subscribe_project_conversation') {
        channels.push((args?.onUpdate as { onmessage: (value: unknown) => void }).onmessage)
        subscriptions += 1
        return `018f2e3a-7000-7000-8000-${String(120 + subscriptions).padStart(12, '0')}`
      }
      if (command === 'open_project_conversation') {
        return reconciled
      }
    })

    const snapshots: number[] = []
    const unsubscribe = await subscribeProjectConversation(
      7,
      snapshot,
      value => snapshots.push(value.projectionRevision),
      invoke,
    )
    channels[0]?.({ ...update, projectionRevision: 5, streamVersion: 5 })

    await vi.waitFor(() => expect(channels).toHaveLength(2))
    expect(order).toEqual([
      'subscribe_project_conversation',
      'cancel_conversation_subscription',
      'open_project_conversation',
      'subscribe_project_conversation',
    ])
    expect(snapshots).toEqual([5])

    await unsubscribe()
  })

  it('terminates an incompatible payload without acknowledging or exposing unknown data', async () => {
    let onmessage: ((value: unknown) => void) | undefined
    const invoke = vi.fn(async (command: string, args?: Record<string, unknown>) => {
      if (command === 'subscribe_project_conversation') {
        onmessage = (args?.onUpdate as { onmessage: (value: unknown) => void }).onmessage
        return '018f2e3a-7000-7000-8000-000000000120'
      }
    })
    const values: ConversationSnapshot[] = []

    await subscribeProjectConversation(7, snapshot, value => values.push(value), invoke)
    onmessage?.({ ...update, secretCursor: 'forbidden' })

    await vi.waitFor(() => {
      expect(values.at(-1)?.recovery).toBe('incompatible')
      expect(invoke).toHaveBeenCalledWith('cancel_conversation_subscription', {
        subscriptionId: '018f2e3a-7000-7000-8000-000000000120',
      })
    })
    expect(invoke).not.toHaveBeenCalledWith(
      'ack_conversation_update',
      expect.anything(),
    )
    expect(JSON.stringify(values)).not.toContain('secretCursor')
  })
})
