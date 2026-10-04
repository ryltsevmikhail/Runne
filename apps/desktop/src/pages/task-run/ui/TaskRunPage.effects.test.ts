import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { defineComponent, h, shallowRef, type Ref } from 'vue'
import { describe, expect, it } from 'vitest'

import { provideRuntimeSession, type RuntimeSessionContext, type RuntimeSessionSnapshot } from '@/app/providers/runtime-session'
import type { TaskRunEffects, TaskRunTimeline } from '@/entities/task-run'
import TaskRunPage from './TaskRunPage.vue'

const id = '018f2e3a-7000-7000-8000-000000000210'
const timeline = (streamVersion: number): TaskRunTimeline => ({ taskRunId: id, projectionRevision: streamVersion, streamVersion, state: 'running', activeAttemptId: null, terminal: null, entries: [], recovery: 'live' })
const effects = (streamVersion: number): TaskRunEffects => ({
  taskRunId: id,
  streamVersion,
  attemptId: null,
  cancellationRequested: true,
  localCommand: null,
  remote: { outcome: 'completed', publication: 'unknown', accounting: 'unknown', cancellation: 'requested', availability: 'available', capabilities: { statusCheck: true, streamResume: false, remoteCancel: true }, usageKnown: null },
  successor: 'blocked',
})

function renderPage(loadTaskRun: () => Promise<TaskRunTimeline>, loadEffects: () => Promise<TaskRunEffects>, onOpen: (value: TaskRunTimeline) => void = () => {}) {
  const live = shallowRef<RuntimeSessionSnapshot>({ runtime: 'live', status: 'live', canMutate: true })
  const context: RuntimeSessionContext = { snapshot: live as Readonly<Ref<RuntimeSessionSnapshot>>, connect: async () => live.value, retry: async () => live.value, close: async () => {}, observeBootstrap: () => live.value, sessionTicket: () => 0, ticketFenced: () => false }
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/task-runs/:taskRunId', component: TaskRunPage }] })
  return router.push(`/task-runs/${id}`).then(async () => {
    await router.isReady()
    const Harness = defineComponent({ setup: () => { provideRuntimeSession(context); return () => h(TaskRunPage, {
      loadTaskRun,
      loadEffects,
      subscribeTaskRun: async (_id, initial) => { onOpen(initial); return { unsubscribe: async () => {}, resync: async () => initial } },
    }) } })
    return mount(Harness, { global: { plugins: [router] } })
  })
}

describe('TaskRun effects version binding', () => {
  it('refreshes the timeline and effects together when their versions differ', async () => {
    let timelineReads = 0
    let effectReads = 0
    let openedAtVersion = 0
    const wrapper = await renderPage(
      async () => timeline(++timelineReads === 1 ? 4 : 5),
      async () => { effectReads += 1; return effects(5) },
      value => { openedAtVersion = value.streamVersion },
    )
    await flushPromises()
    expect(timelineReads).toBe(2)
    expect(effectReads).toBe(2)
    expect(openedAtVersion).toBe(5)
    expect(wrapper.text()).toContain('Remote outcome: completed')
    wrapper.unmount()
  })

  it('keeps mismatched effect facts hidden and reports the refresh state', async () => {
    let timelineReads = 0
    let effectReads = 0
    const wrapper = await renderPage(
      async () => timeline(++timelineReads === 1 ? 4 : 6),
      async () => { effectReads += 1; return effects(5) },
    )
    await flushPromises()
    expect(wrapper.text()).toContain('Execution effects are being refreshed')
    expect(wrapper.text()).not.toContain('Remote outcome: completed')
    expect(effectReads).toBe(2)
    wrapper.unmount()
  })
})
