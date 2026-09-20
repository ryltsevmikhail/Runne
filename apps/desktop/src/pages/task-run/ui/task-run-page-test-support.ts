import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { createMemoryHistory, createRouter, type Router } from 'vue-router'
import { defineComponent, h, nextTick, shallowRef, type Ref } from 'vue'

import { provideRuntimeSession, type RuntimeSessionContext, type RuntimeSessionSnapshot } from '@/app/providers/runtime-session'
import type { TaskRunSession, TaskRunTimeline } from '@/entities/task-run'

import TaskRunPage from './TaskRunPage.vue'

export const taskRunId = '018f2e3a-7000-7000-8000-000000000210'
export const otherTaskRunId = '018f2e3a-7000-7000-8000-000000000211'
export const entryId = '018f2e3a-7000-7000-8000-000000000212'

export const committedEntry = { eventId: entryId, sequence: 1, committedAt: 42, kind: 'attempt_started' as const, attemptId: null }

export const liveTimeline: TaskRunTimeline = { taskRunId, projectionRevision: 1, streamVersion: 1, state: 'running', activeAttemptId: null, terminal: null, entries: [committedEntry], recovery: 'live' }
export const failedTimeline: TaskRunTimeline = { ...liveTimeline, state: 'failed', terminal: 'failure' }

export function timelineWith(recovery: TaskRunTimeline['recovery']): TaskRunTimeline {
  return { ...liveTimeline, recovery }
}

export function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>(value => { resolve = value })
  return { promise, resolve }
}

export type LoadTaskRunFake = (id: string) => Promise<TaskRunTimeline>
export type SubscribeTaskRunFake = (id: string, initial: TaskRunTimeline, onTimeline: (value: TaskRunTimeline) => void) => Promise<TaskRunSession>

function defaultSession(): TaskRunSession {
  return { unsubscribe: async () => {}, resync: async () => liveTimeline }
}

export interface RuntimeHarness {
  context: RuntimeSessionContext
  snapshot: Ref<RuntimeSessionSnapshot>
  live: () => void
  stale: () => void
  empty: () => void
}

export function createRuntimeHarness(): RuntimeHarness {
  const snapshot = shallowRef<RuntimeSessionSnapshot>({ runtime: 'live', status: 'live', canMutate: true })
  const context: RuntimeSessionContext = { snapshot: snapshot as Readonly<Ref<RuntimeSessionSnapshot>>, connect: async () => snapshot.value, retry: async () => snapshot.value, close: async () => {}, observeBootstrap: () => snapshot.value, sessionTicket: () => 0, ticketFenced: () => false }
  return {
    context,
    snapshot,
    live: () => { snapshot.value = { runtime: 'live', status: 'live', canMutate: true } },
    stale: () => { snapshot.value = { runtime: 'authenticated', status: 'stale', canMutate: false } },
    empty: () => { snapshot.value = { runtime: 'unconfigured', status: 'empty', canMutate: false } },
  }
}

export interface TaskRunPageHarnessOptions {
  loadTaskRun?: LoadTaskRunFake
  subscribeTaskRun?: SubscribeTaskRunFake
  openBlockedTaskRun?: SubscribeTaskRunFake
  initialStatus?: 'live' | 'stale' | 'empty'
  taskRunId?: string
}

export interface TaskRunPageHarness {
  wrapper: VueWrapper
  router: Router
  runtime: RuntimeHarness
  navigate: (id: string) => Promise<void>
  settle: () => Promise<void>
}

export async function mountTaskRunPage(options: TaskRunPageHarnessOptions = {}): Promise<TaskRunPageHarness> {
  const runtime = createRuntimeHarness()
  if (options.initialStatus === 'stale') runtime.stale()
  if (options.initialStatus === 'empty') runtime.empty()
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/task-runs/:taskRunId', component: TaskRunPage }] })
  const target = options.taskRunId ?? taskRunId
  await router.push(`/task-runs/${target}`)
  await router.isReady()
  const Harness = defineComponent({
    setup: () => {
      provideRuntimeSession(runtime.context)
      return () => h(TaskRunPage, {
        loadTaskRun: options.loadTaskRun ?? (async () => liveTimeline),
        subscribeTaskRun: options.subscribeTaskRun ?? (async () => defaultSession()),
        openBlockedTaskRun: options.openBlockedTaskRun ?? (async () => defaultSession()),
      })
    },
  })
  const wrapper = mount(Harness, { global: { plugins: [router] } })
  await flushPromises()
  return {
    wrapper,
    router,
    runtime,
    navigate: async (id: string) => { await router.push(`/task-runs/${id}`); await flushPromises() },
    settle: async () => { await flushPromises(); await nextTick(); await flushPromises() },
  }
}
