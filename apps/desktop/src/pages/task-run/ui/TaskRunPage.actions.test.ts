import { flushPromises } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { cancelTaskRun, type TaskRunCancellation, type TaskRunTimeline } from '@/entities/task-run'

import {
  deferred,
  failedTimeline,
  liveTimeline,
  mountTaskRunPage,
  taskRunId,
  timelineWith,
} from './task-run-page-test-support'

vi.mock('@/entities/task-run', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/entities/task-run')>()
  return { ...actual, cancelTaskRun: vi.fn() }
})

const mockedCancel = vi.mocked(cancelTaskRun)

describe('TaskRun page actions', () => {
  beforeEach(() => { mockedCancel.mockReset() })

  it('shows the terminal result and suppresses cancellation for a failed task run', async () => {
    mockedCancel.mockResolvedValue({ taskRunId, streamVersion: 2 })
    const { wrapper, settle } = await mountTaskRunPage({ loadTaskRun: async () => failedTimeline })
    expect(wrapper.text()).toContain('Terminal result: failure')
    expect(wrapper.find('[data-task-run-action="cancel"]').exists()).toBe(false)
    expect(wrapper.find('button').exists()).toBe(false)
    expect(mockedCancel).not.toHaveBeenCalled()
    await settle()
    expect(mockedCancel).not.toHaveBeenCalled()
  })

  it('issues exactly one cancel request per explicit action', async () => {
    const pending = deferred<TaskRunCancellation>()
    mockedCancel.mockReturnValue(pending.promise)
    const { wrapper } = await mountTaskRunPage()
    const cancel = wrapper.get('[data-task-run-action="cancel"]')
    await cancel.trigger('click')
    await cancel.trigger('click')
    await flushPromises()
    expect(mockedCancel).toHaveBeenCalledTimes(1)
    expect(mockedCancel).toHaveBeenCalledWith(taskRunId, 1)
    pending.resolve({ taskRunId, streamVersion: 2 })
    await flushPromises()
    await flushPromises()
    expect(wrapper.find('[data-task-run-action="cancel"]').exists()).toBe(false)
    expect(mockedCancel).toHaveBeenCalledTimes(1)
  })

  it('issues exactly one resync request per explicit action', async () => {
    const pending = deferred<TaskRunTimeline>()
    let resyncs = 0
    const { wrapper, settle } = await mountTaskRunPage({
      loadTaskRun: async () => timelineWith('resync_required'),
      openBlockedTaskRun: async () => ({ unsubscribe: async () => {}, resync: async () => { resyncs += 1; return pending.promise } }),
    })
    await wrapper.get('button').trigger('click')
    await wrapper.get('button').trigger('click')
    await flushPromises()
    expect(resyncs).toBe(1)
    pending.resolve(timelineWith('resync_required'))
    await settle()
    expect(resyncs).toBe(1)
  })

  it('enables the resync action only for resync_required while the runtime is live', async () => {
    const { wrapper, runtime } = await mountTaskRunPage({ loadTaskRun: async () => timelineWith('resync_required') })
    expect(wrapper.text()).toContain('Replay recovery needs revalidation.')
    expect(wrapper.get('button').attributes('disabled')).toBeUndefined()
    runtime.stale()
    await flushPromises()
    expect(wrapper.get('button').attributes('disabled')).toBeDefined()
    runtime.live()
    await flushPromises()
    expect(wrapper.get('button').attributes('disabled')).toBeUndefined()
  })

  it('leaves revoked access as a dead end without actions', async () => {
    const { wrapper } = await mountTaskRunPage({ loadTaskRun: async () => timelineWith('revoked') })
    expect(wrapper.text()).toContain('Access to this task run was revoked.')
    expect(wrapper.find('[role="alert"]').exists()).toBe(true)
    expect(wrapper.find('button').exists()).toBe(false)
    expect(wrapper.text()).not.toContain('Replay recovery needs revalidation.')
    expect(mockedCancel).not.toHaveBeenCalled()
  })

  it('shows the operation error alert above an already loaded snapshot', async () => {
    mockedCancel.mockRejectedValue(new Error('cancel rejected'))
    const { wrapper } = await mountTaskRunPage({ loadTaskRun: async () => liveTimeline })
    await wrapper.get('[data-task-run-action="cancel"]').trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('The last operation failed')
    expect(wrapper.text()).toContain('The displayed data has not changed.')
    expect(wrapper.get('h1').text()).toBe('running')
    expect(wrapper.text()).not.toContain('Last confirmed snapshot')
  })
})
