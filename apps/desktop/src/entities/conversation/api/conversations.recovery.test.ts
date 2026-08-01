import { describe, expect, it, vi } from 'vitest'

import { subscribeProjectConversation } from './conversations'
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

describe('conversation IPC recovery lifecycle', () => {
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

    const session = await subscribeProjectConversation(
      7,
      snapshot,
      value => order.push(`render:${value.projectionRevision}`),
      invoke,
    )
    onmessage?.(update)
    await vi.waitFor(() => expect(order).toEqual(['render:4', 'ack:4']))

    await session.unsubscribe()
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
    const session = await subscribeProjectConversation(
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

    await session.unsubscribe()
  })

  it('explicitly resyncs a retention-gap session through a fresh open and subscription', async () => {
    const order: string[] = []
    const channels: Array<(value: unknown) => void> = []
    let subscriptions = 0
    const invoke = vi.fn(async (command: string, args?: Record<string, unknown>) => {
      order.push(command)
      if (command === 'subscribe_project_conversation') {
        channels.push((args?.onUpdate as { onmessage: (value: unknown) => void }).onmessage)
        subscriptions += 1
        return `018f2e3a-7000-7000-8000-${String(120 + subscriptions).padStart(12, '0')}`
      }
      if (command === 'resync_project_conversation') {
        return snapshot
      }
    })
    const recoveries: string[] = []
    const session = await subscribeProjectConversation(
      7,
      snapshot,
      value => recoveries.push(value.recovery),
      invoke,
    )
    channels[0]?.({ kind: 'error', code: 'replay_resync_required' })
    await vi.waitFor(() => expect(recoveries.at(-1)).toBe('resync_required'))

    const restored = await session.resync()

    expect(restored.recovery).toBe('live')
    expect(recoveries).toEqual(['resync_required', 'reconnecting', 'live'])
    expect(order).toEqual([
      'subscribe_project_conversation',
      'cancel_conversation_subscription',
      'resync_project_conversation',
      'subscribe_project_conversation',
    ])
    await session.unsubscribe()
  })

  it('returns a failed explicit resync to the actionable closed state', async () => {
    let onmessage: ((value: unknown) => void) | undefined
    const invoke = vi.fn(async (command: string, args?: Record<string, unknown>) => {
      if (command === 'subscribe_project_conversation') {
        onmessage = (args?.onUpdate as { onmessage: (value: unknown) => void }).onmessage
        return '018f2e3a-7000-7000-8000-000000000120'
      }
      if (command === 'resync_project_conversation') {
        throw new Error('retention still unavailable')
      }
    })
    const recoveries: string[] = []
    const session = await subscribeProjectConversation(
      7,
      snapshot,
      value => recoveries.push(value.recovery),
      invoke,
    )
    onmessage?.({ kind: 'error', code: 'replay_resync_required' })
    await vi.waitFor(() => expect(recoveries.at(-1)).toBe('resync_required'))

    await expect(session.resync()).rejects.toThrow('retention still unavailable')

    expect(recoveries.slice(-2)).toEqual(['reconnecting', 'resync_required'])
    await session.unsubscribe()
  })

  it('retries only subscription after native resync succeeds but replacement subscription fails', async () => {
    let onmessage: ((value: unknown) => void) | undefined
    let subscriptions = 0
    const invoke = vi.fn(async (command: string, args?: Record<string, unknown>) => {
      if (command === 'subscribe_project_conversation') {
        subscriptions += 1
        if (subscriptions === 2) {
          throw new Error('replacement subscription unavailable')
        }
        onmessage = (args?.onUpdate as { onmessage: (value: unknown) => void }).onmessage
        return '018f2e3a-7000-7000-8000-000000000120'
      }
      if (command === 'resync_project_conversation') {
        return snapshot
      }
    })
    const recoveries: string[] = []
    const session = await subscribeProjectConversation(
      7,
      snapshot,
      value => recoveries.push(value.recovery),
      invoke,
    )
    onmessage?.({ kind: 'error', code: 'replay_resync_required' })
    await vi.waitFor(() => expect(recoveries.at(-1)).toBe('resync_required'))

    await expect(session.resync()).rejects.toThrow('replacement subscription unavailable')

    expect(recoveries).toEqual([
      'resync_required',
      'reconnecting',
      'resync_required',
    ])
    expect(invoke).toHaveBeenCalledTimes(4)

    const restored = await session.resync()

    expect(restored.recovery).toBe('live')
    expect(recoveries.slice(-2)).toEqual(['reconnecting', 'live'])
    expect(invoke).toHaveBeenCalledTimes(5)
    expect(invoke.mock.calls.filter(([command]) => command === 'resync_project_conversation')).toHaveLength(1)
    await session.unsubscribe()
  })

})
