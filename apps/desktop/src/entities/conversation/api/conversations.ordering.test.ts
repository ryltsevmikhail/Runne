import { describe, expect, it, vi } from 'vitest'

import { subscribeProjectConversation } from './conversations'
import type { ConversationSnapshot } from './conversations'
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

describe('conversation IPC ordering and termination', () => {
  it('advances a successful send in the session before processing the next live update', async () => {
    let onmessage: ((value: unknown) => void) | undefined
    const sentSnapshot = {
      ...snapshot,
      projectionRevision: 4,
      streamVersion: 4,
      messages: [...snapshot.messages, update.message],
    }
    const nextUpdate = {
      ...update,
      projectionRevision: 5,
      streamVersion: 5,
      message: {
        ...update.message,
        messageId: '018f2e3a-7000-7000-8000-000000000107',
        text: 'after send',
        committedAt: 1_753_800_000_004,
      },
    }
    const invoke = vi.fn(async (command: string, args?: Record<string, unknown>) => {
      if (command === 'subscribe_project_conversation') {
        onmessage = (args?.onUpdate as { onmessage: (value: unknown) => void }).onmessage
        return '018f2e3a-7000-7000-8000-000000000120'
      }
      if (command === 'send_project_message') {
        return sentSnapshot
      }
    })
    const revisions: number[] = []

    const session = await subscribeProjectConversation(
      7,
      snapshot,
      value => revisions.push(value.projectionRevision),
      invoke,
    )
    await session.sendMessage('hello')
    onmessage?.(nextUpdate)

    await vi.waitFor(() => expect(revisions).toEqual([4, 5]))
    expect(invoke).not.toHaveBeenCalledWith('open_project_conversation', expect.anything())
    expect(invoke).not.toHaveBeenCalledWith(
      'cancel_conversation_subscription',
      expect.anything(),
    )
    expect(invoke).toHaveBeenCalledWith('ack_conversation_update', {
      subscriptionId: '018f2e3a-7000-7000-8000-000000000120',
      projectionRevision: 5,
    })

    await session.unsubscribe()
  })

  it.each([
    ['a different existing message', snapshot.messages[0]],
    ['no message', null],
  ] as const)(
    'cancels without ack for a same-revision initial update with %s',
    async (_case, message) => {
      let onmessage: ((value: unknown) => void) | undefined
      const invoke = vi.fn(async (command: string, args?: Record<string, unknown>) => {
        if (command === 'subscribe_project_conversation') {
          onmessage = (args?.onUpdate as { onmessage: (value: unknown) => void }).onmessage
          return '018f2e3a-7000-7000-8000-000000000120'
        }
      })
      const values: ConversationSnapshot[] = []

      const session = await subscribeProjectConversation(
        7,
        snapshot,
        value => values.push(value),
        invoke,
      )
      onmessage?.({
        ...update,
        projectionRevision: snapshot.projectionRevision,
        streamVersion: snapshot.streamVersion,
        message,
      })

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

      await session.unsubscribe()
    },
  )

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
