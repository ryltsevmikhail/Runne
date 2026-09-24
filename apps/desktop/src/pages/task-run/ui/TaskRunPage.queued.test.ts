import { describe, expect, it, vi } from 'vitest'
import type { TaskRunTimeline } from '@/entities/task-run'
import { liveTimeline, mountTaskRunPage } from './task-run-page-test-support'

describe('queued TaskRun page', () => {
  it('loads the durably queued snapshot and subscribes to its timeline', async () => {
    const queued: TaskRunTimeline = { ...liveTimeline, projectionRevision: 2, streamVersion: 2, state: 'queued', activeAttemptId: null, entries: [] }
    const loadTaskRun = vi.fn(async () => queued)
    const subscribeTaskRun = vi.fn(async () => ({ unsubscribe: async () => {}, resync: async () => queued }))
    const { wrapper } = await mountTaskRunPage({ loadTaskRun, subscribeTaskRun })

    expect(loadTaskRun).toHaveBeenCalledWith(queued.taskRunId)
    expect(subscribeTaskRun).toHaveBeenCalledWith(queued.taskRunId, queued, expect.any(Function))
    expect(wrapper.text()).toContain('Task run has no recorded events yet.')
    expect(wrapper.find('button').exists()).toBe(true)
  })
})
