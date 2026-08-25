import { describe, expect, it, vi } from 'vitest'

import { subscribeTaskRunTimeline, type TaskRunTimeline } from './task-run'

vi.mock('@tauri-apps/api/core', () => ({ Channel: class { constructor(readonly onmessage: (value: unknown) => void) {} }, invoke: vi.fn() }))

const id = '018f2e3a-7000-7000-8000-000000000210'
const snapshot: TaskRunTimeline = { taskRunId: id, projectionRevision: 0, streamVersion: 0, state: 'running', activeAttemptId: null, terminal: null, entries: [], recovery: 'live' }

describe('TaskRun subscription lifecycle', () => {
  it('renders a streamed delivery before acknowledging its durable revision', async () => {
    let delivery: ((value: unknown) => void) | undefined
    const order: string[] = []
    const invoke = vi.fn(async (command: string, args?: Record<string, unknown>) => {
      if (command === 'subscribe_task_run_timeline') { delivery = (args?.onUpdate as { onmessage: (value: unknown) => void }).onmessage; return '018f2e3a-7000-7000-8000-000000000220' }
      if (command === 'ack_task_run_update') order.push(`ack:${String(args?.projectionRevision)}`)
    })
    const session = await subscribeTaskRunTimeline(id, snapshot, value => order.push(`render:${value.projectionRevision}`), invoke)
    delivery?.({ kind: 'update', taskRunId: id, projectionRevision: 1, streamVersion: 1, entry: { eventId: '018f2e3a-7000-7000-8000-000000000211', sequence: 1, committedAt: 1, kind: 'attempt_started', attemptId: null }, recovery: 'live' })
    await vi.waitFor(() => expect(order).toEqual(['render:1', 'ack:1']))
    await session.unsubscribe()
  })

  it('buffers a synchronous first update until its subscription ID can acknowledge it', async () => {
    const order: string[] = []
    const invoke = vi.fn((command: string, args?: Record<string, unknown>) => {
      if (command === 'subscribe_task_run_timeline') {
        const delivery = (args?.onUpdate as { onmessage: (value: unknown) => void }).onmessage
        delivery({ kind: 'update', taskRunId: id, projectionRevision: 1, streamVersion: 1, entry: null, recovery: 'live' })
        return Promise.resolve('018f2e3a-7000-7000-8000-000000000220')
      }
      if (command === 'ack_task_run_update') order.push(`ack:${String(args?.projectionRevision)}`)
      return Promise.resolve(undefined)
    })
    const session = await subscribeTaskRunTimeline(id, snapshot, value => order.push(`render:${value.projectionRevision}`), invoke)
    expect(order).toEqual(['render:1', 'ack:1'])
    await session.unsubscribe()
  })

  it('buffers a synchronous first terminal error without cancelling its released subscription', async () => {
    const invoke = vi.fn((command: string, args?: Record<string, unknown>) => {
      if (command === 'subscribe_task_run_timeline') {
        const delivery = (args?.onUpdate as { onmessage: (value: unknown) => void }).onmessage
        delivery({ kind: 'error', code: 'replay_resync_required' })
        return Promise.resolve('018f2e3a-7000-7000-8000-000000000220')
      }
      return Promise.resolve(undefined)
    })
    const recoveries: string[] = []
    await subscribeTaskRunTimeline(id, snapshot, value => recoveries.push(value.recovery), invoke)
    expect(recoveries).toEqual(['resync_required'])
    expect(invoke).not.toHaveBeenCalledWith('cancel_task_run_subscription', expect.anything())
  })

  it('enters persisted resync recovery and uses only the read-only resync route', async () => {
    let delivery: ((value: unknown) => void) | undefined
    const invoke = vi.fn(async (command: string, args?: Record<string, unknown>) => {
      if (command === 'subscribe_task_run_timeline') { delivery = (args?.onUpdate as { onmessage: (value: unknown) => void }).onmessage; return '018f2e3a-7000-7000-8000-000000000220' }
      if (command === 'resync_task_run_timeline') return { ...snapshot, recovery: 'resync_required' }
    })
    const updates: string[] = []
    const session = await subscribeTaskRunTimeline(id, snapshot, value => updates.push(value.recovery), invoke)
    delivery?.({ kind: 'error', code: 'replay_resync_required' })
    await vi.waitFor(() => expect(updates).toEqual(['resync_required']))
    await expect(session.resync()).resolves.toMatchObject({ recovery: 'resync_required' })
    expect(invoke).toHaveBeenCalledWith('resync_task_run_timeline', { taskRunId: id })
    await session.unsubscribe()
  })

  it('keeps terminal resync recovery callable after native cleanup has released its slot', async () => {
    let delivery: ((value: unknown) => void) | undefined
    const recoveries: string[] = []
    const invoke = vi.fn(async (command: string, args?: Record<string, unknown>) => {
      if (command === 'subscribe_task_run_timeline') { delivery = (args?.onUpdate as { onmessage: (value: unknown) => void }).onmessage; return '018f2e3a-7000-7000-8000-000000000220' }
      if (command === 'resync_task_run_timeline') return { ...snapshot, recovery: 'resync_required' }
      if (command === 'cancel_task_run_subscription') throw new Error('task_run_subscription_unavailable')
    })
    const session = await subscribeTaskRunTimeline(id, snapshot, value => recoveries.push(value.recovery), invoke)
    delivery?.({ kind: 'error', code: 'replay_resync_required' })
    await vi.waitFor(() => expect(recoveries.at(-1)).toBe('resync_required'))
    await expect(session.resync()).resolves.toMatchObject({ recovery: 'resync_required' })
    expect(invoke).not.toHaveBeenCalledWith('cancel_task_run_subscription', expect.anything())
    delivery?.({ kind: 'update', taskRunId: id, projectionRevision: 1, streamVersion: 1, entry: null, recovery: 'live' })
    await new Promise(resolve => setTimeout(resolve, 0))
    expect(recoveries).toEqual(['resync_required', 'resync_required'])
  })

  it('fails closed on a malformed callback and ignores later native deliveries', async () => {
    let delivery: ((value: unknown) => void) | undefined
    const recoveries: string[] = []
    const invoke = vi.fn(async (command: string, args?: Record<string, unknown>) => {
      if (command === 'subscribe_task_run_timeline') { delivery = (args?.onUpdate as { onmessage: (value: unknown) => void }).onmessage; return '018f2e3a-7000-7000-8000-000000000220' }
      if (command === 'cancel_task_run_subscription') return undefined
    })
    const session = await subscribeTaskRunTimeline(id, snapshot, value => recoveries.push(value.recovery), invoke)
    delivery?.({ kind: 'update', taskRunId: id, projectionRevision: 1, streamVersion: 1, entry: null, recovery: 'unknown' })
    await vi.waitFor(() => expect(recoveries).toEqual(['reconnecting']))
    expect(invoke).toHaveBeenCalledWith('cancel_task_run_subscription', { subscriptionId: '018f2e3a-7000-7000-8000-000000000220' })
    delivery?.({ kind: 'update', taskRunId: id, projectionRevision: 1, streamVersion: 1, entry: null, recovery: 'live' })
    await new Promise(resolve => setTimeout(resolve, 0))
    expect(recoveries).toEqual(['reconnecting'])
    await expect(session.unsubscribe()).rejects.toThrow('Invalid TaskRun delivery')
  })

  it('fails closed when a native error code is unknown and ignores later deliveries', async () => {
    let delivery: ((value: unknown) => void) | undefined
    const recoveries: string[] = []
    const invoke = vi.fn(async (command: string, args?: Record<string, unknown>) => {
      if (command === 'subscribe_task_run_timeline') { delivery = (args?.onUpdate as { onmessage: (value: unknown) => void }).onmessage; return '018f2e3a-7000-7000-8000-000000000220' }
      if (command === 'cancel_task_run_subscription') return undefined
    })
    const session = await subscribeTaskRunTimeline(id, snapshot, value => recoveries.push(value.recovery), invoke)
    delivery?.({ kind: 'error', code: 'unexpected_native_error' })
    await vi.waitFor(() => expect(recoveries).toEqual(['reconnecting']))
    expect(invoke).toHaveBeenCalledWith('cancel_task_run_subscription', { subscriptionId: '018f2e3a-7000-7000-8000-000000000220' })
    delivery?.({ kind: 'update', taskRunId: id, projectionRevision: 1, streamVersion: 1, entry: null, recovery: 'live' })
    await new Promise(resolve => setTimeout(resolve, 0))
    expect(recoveries).toEqual(['reconnecting'])
    await expect(session.unsubscribe()).rejects.toThrow('Invalid TaskRun delivery')
  })

  it('renders native unexpected completion as a closed reconnecting snapshot', async () => {
    let delivery: ((value: unknown) => void) | undefined
    const invoke = vi.fn(async (command: string, args?: Record<string, unknown>) => {
      if (command === 'subscribe_task_run_timeline') { delivery = (args?.onUpdate as { onmessage: (value: unknown) => void }).onmessage; return '018f2e3a-7000-7000-8000-000000000220' }
    })
    const recoveries: string[] = []
    await subscribeTaskRunTimeline(id, snapshot, value => recoveries.push(value.recovery), invoke)
    delivery?.({ kind: 'error', code: 'task_run_subscription_unavailable' })
    await vi.waitFor(() => expect(recoveries).toEqual(['reconnecting']))
  })

  it('propagates a native cancellation failure to the session owner', async () => {
    const invoke = vi.fn(async (command: string) => {
      if (command === 'subscribe_task_run_timeline') return '018f2e3a-7000-7000-8000-000000000220'
      if (command === 'cancel_task_run_subscription') throw new Error('termination unresolved')
    })
    const session = await subscribeTaskRunTimeline(id, snapshot, () => {}, invoke)
    await expect(session.unsubscribe()).rejects.toThrow('termination unresolved')
  })

  it('closes to reconnecting when gap cancellation rejects and ignores later deliveries', async () => {
    let delivery: ((value: unknown) => void) | undefined
    const recoveries: string[] = []
    const invoke = vi.fn(async (command: string, args?: Record<string, unknown>) => {
      if (command === 'subscribe_task_run_timeline') { delivery = (args?.onUpdate as { onmessage: (value: unknown) => void }).onmessage; return '018f2e3a-7000-7000-8000-000000000220' }
      if (command === 'get_task_run_timeline') return { ...snapshot, projectionRevision: 1, streamVersion: 1 }
      if (command === 'cancel_task_run_subscription') throw new Error('termination unresolved')
    })
    const session = await subscribeTaskRunTimeline(id, snapshot, value => recoveries.push(value.recovery), invoke)
    delivery?.({ kind: 'update', taskRunId: id, projectionRevision: 2, streamVersion: 2, entry: null, recovery: 'live' })
    await vi.waitFor(() => expect(recoveries).toEqual(['live', 'reconnecting']))
    delivery?.({ kind: 'update', taskRunId: id, projectionRevision: 2, streamVersion: 2, entry: null, recovery: 'live' })
    await new Promise(resolve => setTimeout(resolve, 0))
    expect(recoveries).toEqual(['live', 'reconnecting'])
    await expect(session.unsubscribe()).rejects.toThrow('termination unresolved')
  })
})
