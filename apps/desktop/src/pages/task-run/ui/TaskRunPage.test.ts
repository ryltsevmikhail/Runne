import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { defineComponent, h, shallowRef, type Ref } from 'vue'
import { describe, expect, it } from 'vitest'

import { provideRuntimeSession, type RuntimeSessionContext, type RuntimeSessionSnapshot } from '@/app/providers/runtime-session'
import type { TaskRunTimeline } from '@/entities/task-run'
import { currentLocale } from '@/shared/i18n'
import TaskRunPage from './TaskRunPage.vue'

const id = '018f2e3a-7000-7000-8000-000000000210'
const timeline: TaskRunTimeline = { taskRunId: id, projectionRevision: 0, streamVersion: 0, state: 'running', activeAttemptId: null, terminal: null, entries: [], recovery: 'live' }
const otherId = '018f2e3a-7000-7000-8000-000000000211'
const completedOtherTimeline: TaskRunTimeline = { ...timeline, taskRunId: otherId, state: 'succeeded' }

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>(value => { resolve = value })
  return { promise, resolve }
}

describe('TaskRun page runtime session gate', () => {
  it('localizes unavailable state through the owned catalog', async () => {
    const previousLocale = currentLocale.value
    currentLocale.value = 'ru'
    try {
      const live = shallowRef<RuntimeSessionSnapshot>({ runtime: 'live', status: 'live', canMutate: true })
      const context: RuntimeSessionContext = { snapshot: live as Readonly<Ref<RuntimeSessionSnapshot>>, connect: async () => live.value, retry: async () => live.value, close: async () => {}, observeBootstrap: () => live.value, sessionTicket: () => 0, ticketFenced: () => false }
      const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/task-runs/:taskRunId', component: TaskRunPage }] })
      await router.push(`/task-runs/${id}`)
      await router.isReady()
      const Harness = defineComponent({ setup: () => { provideRuntimeSession(context); return () => h(TaskRunPage, { loadTaskRun: async () => { throw new Error('unavailable') } }) } })
      const wrapper = mount(Harness, { global: { plugins: [router] } })
      await flushPromises()
      expect(wrapper.text()).toContain('TaskRun недоступен.')
    } finally {
      currentLocale.value = previousLocale
    }
  })

  it('waits for an injected live session before querying and retries when it becomes live', async () => {
    const snapshot = shallowRef<RuntimeSessionSnapshot>({ runtime: 'authenticated', status: 'stale', canMutate: false })
    const context: RuntimeSessionContext = { snapshot: snapshot as Readonly<Ref<RuntimeSessionSnapshot>>, connect: async () => snapshot.value, retry: async () => snapshot.value, close: async () => {}, observeBootstrap: () => snapshot.value, sessionTicket: () => 0, ticketFenced: () => false }
    const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/task-runs/:taskRunId', component: TaskRunPage }] })
    await router.push(`/task-runs/${id}`)
    await router.isReady()
    let calls = 0
    const Harness = defineComponent({ setup: () => { provideRuntimeSession(context); return () => h(TaskRunPage, { loadTaskRun: async () => { calls += 1; return timeline }, subscribeTaskRun: async () => ({ unsubscribe: async () => {}, resync: async () => timeline }) }) } })
    mount(Harness, { global: { plugins: [router] } })
    await flushPromises()
    expect(calls).toBe(0)
    snapshot.value = { runtime: 'live', status: 'live', canMutate: true }
    await flushPromises()
    expect(calls).toBe(1)
  })

  it('publishes a synchronous first subscription update after the session installs', async () => {
    const live = shallowRef<RuntimeSessionSnapshot>({ runtime: 'live', status: 'live', canMutate: true })
    const context: RuntimeSessionContext = { snapshot: live as Readonly<Ref<RuntimeSessionSnapshot>>, connect: async () => live.value, retry: async () => live.value, close: async () => {}, observeBootstrap: () => live.value, sessionTicket: () => 0, ticketFenced: () => false }
    const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/task-runs/:taskRunId', component: TaskRunPage }] })
    await router.push(`/task-runs/${id}`)
    await router.isReady()
    const Harness = defineComponent({ setup: () => { provideRuntimeSession(context); return () => h(TaskRunPage, { loadTaskRun: async () => timeline, subscribeTaskRun: async (_id, _initial, onTimeline) => { onTimeline({ ...timeline, state: 'succeeded', recovery: 'live' }); return { unsubscribe: async () => {}, resync: async () => timeline } } }) } })
    const wrapper = mount(Harness, { global: { plugins: [router] } })
    await flushPromises()
    expect(wrapper.get('h1').text()).toBe('completed')
  })

  it('renders a synchronous fail-closed callback as read-only after session installation', async () => {
    const live = shallowRef<RuntimeSessionSnapshot>({ runtime: 'live', status: 'live', canMutate: true })
    const context: RuntimeSessionContext = { snapshot: live as Readonly<Ref<RuntimeSessionSnapshot>>, connect: async () => live.value, retry: async () => live.value, close: async () => {}, observeBootstrap: () => live.value, sessionTicket: () => 0, ticketFenced: () => false }
    const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/task-runs/:taskRunId', component: TaskRunPage }] })
    await router.push(`/task-runs/${id}`)
    await router.isReady()
    const Harness = defineComponent({ setup: () => { provideRuntimeSession(context); return () => h(TaskRunPage, { loadTaskRun: async () => timeline, subscribeTaskRun: async (_id, _initial, onTimeline) => { onTimeline({ ...timeline, recovery: 'reconnecting' }); return { unsubscribe: async () => {}, resync: async () => timeline } } }) } })
    const wrapper = mount(Harness, { global: { plugins: [router] } })
    await flushPromises()
    expect(wrapper.text()).toContain('Task run is read-only')
    expect(wrapper.text()).toContain('reconnecting')
  })

  it('releases the native session slot when runtime status leaves live', async () => {
    const live = shallowRef<RuntimeSessionSnapshot>({ runtime: 'live', status: 'live', canMutate: true })
    const context: RuntimeSessionContext = { snapshot: live as Readonly<Ref<RuntimeSessionSnapshot>>, connect: async () => live.value, retry: async () => live.value, close: async () => {}, observeBootstrap: () => live.value, sessionTicket: () => 0, ticketFenced: () => false }
    const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/task-runs/:taskRunId', component: TaskRunPage }] })
    await router.push(`/task-runs/${id}`)
    await router.isReady()
    let nativeSlots = 0
    let unsubscribes = 0
    const Harness = defineComponent({ setup: () => { provideRuntimeSession(context); return () => h(TaskRunPage, { loadTaskRun: async () => timeline, subscribeTaskRun: async () => { nativeSlots += 1; return { unsubscribe: async () => { nativeSlots -= 1; unsubscribes += 1 }, resync: async () => timeline } } }) } })
    const wrapper = mount(Harness, { global: { plugins: [router] } })
    await flushPromises()
    expect(nativeSlots).toBe(1)
    live.value = { runtime: 'authenticated', status: 'stale', canMutate: false }
    await flushPromises()
    expect(unsubscribes).toBe(1)
    expect(nativeSlots).toBe(0)
    expect(wrapper.text()).toContain('Task run is read-only')
    expect(wrapper.text()).toContain('reconnecting')
    expect(wrapper.find('button').exists()).toBe(false)
  })

  it('waits for teardown before recreating a session after a status bounce', async () => {
    const live = shallowRef<RuntimeSessionSnapshot>({ runtime: 'live', status: 'live', canMutate: true })
    const context: RuntimeSessionContext = { snapshot: live as Readonly<Ref<RuntimeSessionSnapshot>>, connect: async () => live.value, retry: async () => live.value, close: async () => {}, observeBootstrap: () => live.value, sessionTicket: () => 0, ticketFenced: () => false }
    const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/task-runs/:taskRunId', component: TaskRunPage }] })
    await router.push(`/task-runs/${id}`)
    await router.isReady()
    const oldTeardown = deferred<void>()
    let subscriptions = 0
    let oldUnsubscribes = 0
    let newUnsubscribes = 0
    const Harness = defineComponent({ setup: () => { provideRuntimeSession(context); return () => h(TaskRunPage, { loadTaskRun: async () => timeline, subscribeTaskRun: async () => { subscriptions += 1; const current = subscriptions; return { unsubscribe: async () => { if (current === 1) { oldUnsubscribes += 1; await oldTeardown.promise } else newUnsubscribes += 1 }, resync: async () => timeline } } }) } })
    mount(Harness, { global: { plugins: [router] } })
    await flushPromises()
    expect(subscriptions).toBe(1)
    live.value = { runtime: 'authenticated', status: 'stale', canMutate: false }
    await flushPromises()
    expect(oldUnsubscribes).toBe(1)
    live.value = { runtime: 'live', status: 'live', canMutate: true }
    await flushPromises()
    expect(subscriptions).toBe(1)
    oldTeardown.resolve()
    await flushPromises()
    expect(subscriptions).toBe(2)
    live.value = { runtime: 'authenticated', status: 'stale', canMutate: false }
    await flushPromises()
    expect(newUnsubscribes).toBe(1)
  })

  it('does not subscribe when runtime leaves live as a query resolves', async () => {
    const live = shallowRef<RuntimeSessionSnapshot>({ runtime: 'live', status: 'live', canMutate: true })
    const context: RuntimeSessionContext = { snapshot: live as Readonly<Ref<RuntimeSessionSnapshot>>, connect: async () => live.value, retry: async () => live.value, close: async () => {}, observeBootstrap: () => live.value, sessionTicket: () => 0, ticketFenced: () => false }
    const pending = deferred<TaskRunTimeline>()
    const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/task-runs/:taskRunId', component: TaskRunPage }] })
    await router.push(`/task-runs/${id}`)
    await router.isReady()
    let subscriptions = 0
    const Harness = defineComponent({ setup: () => { provideRuntimeSession(context); return () => h(TaskRunPage, { loadTaskRun: async () => { const value = await pending.promise; live.value = { runtime: 'authenticated', status: 'stale', canMutate: false }; return value }, subscribeTaskRun: async () => { subscriptions += 1; return { unsubscribe: async () => {}, resync: async () => timeline } } }) } })
    mount(Harness, { global: { plugins: [router] } })
    await flushPromises()
    pending.resolve(timeline)
    await flushPromises()
    expect(subscriptions).toBe(0)
  })

  it('does not subscribe when runtime leaves live as resync resolves', async () => {
    const live = shallowRef<RuntimeSessionSnapshot>({ runtime: 'live', status: 'live', canMutate: true })
    const context: RuntimeSessionContext = { snapshot: live as Readonly<Ref<RuntimeSessionSnapshot>>, connect: async () => live.value, retry: async () => live.value, close: async () => {}, observeBootstrap: () => live.value, sessionTicket: () => 0, ticketFenced: () => false }
    const blocked = { ...timeline, recovery: 'resync_required' as const }
    const pending = deferred<TaskRunTimeline>()
    const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/task-runs/:taskRunId', component: TaskRunPage }] })
    await router.push(`/task-runs/${id}`)
    await router.isReady()
    let subscriptions = 0
    const Harness = defineComponent({ setup: () => { provideRuntimeSession(context); return () => h(TaskRunPage, { loadTaskRun: async () => blocked, subscribeTaskRun: async () => { subscriptions += 1; return { unsubscribe: async () => {}, resync: async () => timeline } }, openBlockedTaskRun: async () => ({ unsubscribe: async () => {}, resync: async () => { const value = await pending.promise; live.value = { runtime: 'authenticated', status: 'stale', canMutate: false }; return value } }) }) } })
    const wrapper = mount(Harness, { global: { plugins: [router] } })
    await flushPromises()
    await wrapper.get('button').trigger('click')
    pending.resolve(timeline)
    await flushPromises()
    expect(subscriptions).toBe(0)
  })

  it('keeps confirmed data read-only after native subscribe rejection', async () => {
    const live = shallowRef<RuntimeSessionSnapshot>({ runtime: 'live', status: 'live', canMutate: true })
    const context: RuntimeSessionContext = { snapshot: live as Readonly<Ref<RuntimeSessionSnapshot>>, connect: async () => live.value, retry: async () => live.value, close: async () => {}, observeBootstrap: () => live.value, sessionTicket: () => 0, ticketFenced: () => false }
    const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/task-runs/:taskRunId', component: TaskRunPage }] })
    await router.push(`/task-runs/${id}`)
    await router.isReady()
    let delivery: ((value: TaskRunTimeline) => void) | undefined
    const Harness = defineComponent({ setup: () => { provideRuntimeSession(context); return () => h(TaskRunPage, { loadTaskRun: async () => timeline, subscribeTaskRun: async (_id, _initial, onTimeline) => { delivery = onTimeline; onTimeline({ ...timeline, state: 'succeeded', recovery: 'live' }); throw new Error('native subscription rejected') } }) } })
    const wrapper = mount(Harness, { global: { plugins: [router] } })
    await flushPromises()
    expect(wrapper.text()).toContain('Task run is read-only')
    expect(wrapper.text()).toContain('reconnecting')
    expect(wrapper.find('button').exists()).toBe(false)
    delivery?.({ ...timeline, state: 'succeeded', recovery: 'live' })
    await flushPromises()
    expect(wrapper.get('h1').text()).toBe('running')
  })

  it('keeps confirmed data read-only after native unsubscribe rejection', async () => {
    const live = shallowRef<RuntimeSessionSnapshot>({ runtime: 'live', status: 'live', canMutate: true })
    const context: RuntimeSessionContext = { snapshot: live as Readonly<Ref<RuntimeSessionSnapshot>>, connect: async () => live.value, retry: async () => live.value, close: async () => {}, observeBootstrap: () => live.value, sessionTicket: () => 0, ticketFenced: () => false }
    const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/task-runs/:taskRunId', component: TaskRunPage }] })
    await router.push(`/task-runs/${id}`)
    await router.isReady()
    const Harness = defineComponent({ setup: () => { provideRuntimeSession(context); return () => h(TaskRunPage, { loadTaskRun: async () => timeline, subscribeTaskRun: async () => ({ unsubscribe: async () => { throw new Error('native cancellation rejected') }, resync: async () => timeline }) }) } })
    const wrapper = mount(Harness, { global: { plugins: [router] } })
    await flushPromises()
    await router.push(`/task-runs/${otherId}`)
    await flushPromises()
    expect(wrapper.text()).toContain('Task run is read-only')
    expect(wrapper.text()).toContain('reconnecting')
    expect(wrapper.find('button').exists()).toBe(false)
  })

  it('re-enables revalidation after an invalidated resync and live recovery', async () => {
    const live = shallowRef<RuntimeSessionSnapshot>({ runtime: 'live', status: 'live', canMutate: true })
    const context: RuntimeSessionContext = { snapshot: live as Readonly<Ref<RuntimeSessionSnapshot>>, connect: async () => live.value, retry: async () => live.value, close: async () => {}, observeBootstrap: () => live.value, sessionTicket: () => 0, ticketFenced: () => false }
    const blocked = { ...timeline, recovery: 'resync_required' as const }
    const pending = deferred<TaskRunTimeline>()
    const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/task-runs/:taskRunId', component: TaskRunPage }] })
    await router.push(`/task-runs/${id}`)
    await router.isReady()
    let opens = 0
    const Harness = defineComponent({ setup: () => { provideRuntimeSession(context); return () => h(TaskRunPage, { loadTaskRun: async () => blocked, openBlockedTaskRun: async () => { opens += 1; return { unsubscribe: async () => {}, resync: async () => opens === 1 ? pending.promise : blocked } } }) } })
    const wrapper = mount(Harness, { global: { plugins: [router] } })
    await flushPromises()
    await wrapper.get('button').trigger('click')
    live.value = { runtime: 'authenticated', status: 'stale', canMutate: false }
    await flushPromises()
    live.value = { runtime: 'live', status: 'live', canMutate: true }
    await flushPromises()
    expect(opens).toBe(2)
    pending.resolve(blocked)
    await flushPromises()
    expect(wrapper.get('button').attributes('disabled')).toBeUndefined()
  })

  it('offers only an explicit blocked-state revalidation without automatic resubscribe', async () => {
    const live = shallowRef<RuntimeSessionSnapshot>({ runtime: 'live', status: 'live', canMutate: true })
    const context: RuntimeSessionContext = { snapshot: live as Readonly<Ref<RuntimeSessionSnapshot>>, connect: async () => live.value, retry: async () => live.value, close: async () => {}, observeBootstrap: () => live.value, sessionTicket: () => 0, ticketFenced: () => false }
    const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/task-runs/:taskRunId', component: TaskRunPage }] })
    await router.push(`/task-runs/${id}`)
    await router.isReady()
    let subscriptions = 0
    let resyncs = 0
    const blocked = { ...timeline, recovery: 'resync_required' as const }
    const Harness = defineComponent({ setup: () => { provideRuntimeSession(context); return () => h(TaskRunPage, { loadTaskRun: async () => blocked, subscribeTaskRun: async () => { subscriptions += 1; return { unsubscribe: async () => {}, resync: async () => blocked } }, openBlockedTaskRun: async () => ({ unsubscribe: async () => {}, resync: async () => { resyncs += 1; return blocked } }) }) } })
    const wrapper = mount(Harness, { global: { plugins: [router] } })
    await flushPromises()
    await wrapper.get('button').trigger('click')
    await flushPromises()
    expect(resyncs).toBe(1)
    expect(subscriptions).toBe(0)
    expect(wrapper.text()).toContain('resync_required')
  })

  it('creates a native subscription only after explicit resync returns live', async () => {
    const live = shallowRef<RuntimeSessionSnapshot>({ runtime: 'live', status: 'live', canMutate: true })
    const context: RuntimeSessionContext = { snapshot: live as Readonly<Ref<RuntimeSessionSnapshot>>, connect: async () => live.value, retry: async () => live.value, close: async () => {}, observeBootstrap: () => live.value, sessionTicket: () => 0, ticketFenced: () => false }
    const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/task-runs/:taskRunId', component: TaskRunPage }] })
    await router.push(`/task-runs/${id}`)
    await router.isReady()
    let subscriptions = 0
    const blocked = { ...timeline, recovery: 'resync_required' as const }
    const Harness = defineComponent({ setup: () => { provideRuntimeSession(context); return () => h(TaskRunPage, { loadTaskRun: async () => blocked, subscribeTaskRun: async () => { subscriptions += 1; return { unsubscribe: async () => {}, resync: async () => timeline } }, openBlockedTaskRun: async () => ({ unsubscribe: async () => {}, resync: async () => timeline }) }) } })
    const wrapper = mount(Harness, { global: { plugins: [router] } })
    await flushPromises()
    expect(subscriptions).toBe(0)
    await wrapper.get('button').trigger('click')
    await flushPromises()
    expect(subscriptions).toBe(1)
  })

  it('ignores a stale initial route load after navigation', async () => {
    const live = shallowRef<RuntimeSessionSnapshot>({ runtime: 'live', status: 'live', canMutate: true })
    const context: RuntimeSessionContext = { snapshot: live as Readonly<Ref<RuntimeSessionSnapshot>>, connect: async () => live.value, retry: async () => live.value, close: async () => {}, observeBootstrap: () => live.value, sessionTicket: () => 0, ticketFenced: () => false }
    const first = deferred<TaskRunTimeline>()
    const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/task-runs/:taskRunId', component: TaskRunPage }] })
    await router.push(`/task-runs/${id}`)
    await router.isReady()
    const subscriptions: string[] = []
    const Harness = defineComponent({ setup: () => { provideRuntimeSession(context); return () => h(TaskRunPage, { loadTaskRun: async (value: string) => value === id ? first.promise : completedOtherTimeline, subscribeTaskRun: async (value: string) => { subscriptions.push(value); return { unsubscribe: async () => {}, resync: async () => timeline } } }) } })
    const wrapper = mount(Harness, { global: { plugins: [router] } })
    await router.push(`/task-runs/${otherId}`)
    await flushPromises()
    first.resolve(timeline)
    await flushPromises()
    expect(subscriptions).toEqual([otherId])
    expect(wrapper.get('h1').text()).toBe('completed')
  })

  it('does not subscribe a stale resync completion after navigation', async () => {
    const live = shallowRef<RuntimeSessionSnapshot>({ runtime: 'live', status: 'live', canMutate: true })
    const context: RuntimeSessionContext = { snapshot: live as Readonly<Ref<RuntimeSessionSnapshot>>, connect: async () => live.value, retry: async () => live.value, close: async () => {}, observeBootstrap: () => live.value, sessionTicket: () => 0, ticketFenced: () => false }
    const blocked = { ...timeline, recovery: 'resync_required' as const }
    const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/task-runs/:taskRunId', component: TaskRunPage }] })
    await router.push(`/task-runs/${id}`)
    await router.isReady()
    const oldUnsubscribe = deferred<void>()
    const subscriptions: string[] = []
    let oldUnsubscribes = 0
    const Harness = defineComponent({ setup: () => { provideRuntimeSession(context); return () => h(TaskRunPage, { loadTaskRun: async (value: string) => value === id ? blocked : completedOtherTimeline, subscribeTaskRun: async (value: string) => { subscriptions.push(value); return { unsubscribe: async () => {}, resync: async () => timeline } }, openBlockedTaskRun: async () => ({ unsubscribe: async () => { oldUnsubscribes += 1; await oldUnsubscribe.promise }, resync: async () => timeline }) }) } })
    const wrapper = mount(Harness, { global: { plugins: [router] } })
    await flushPromises()
    await wrapper.get('button').trigger('click')
    await flushPromises()
    expect(oldUnsubscribes).toBe(1)
    await router.push(`/task-runs/${otherId}`)
    oldUnsubscribe.resolve()
    await flushPromises()
    expect(subscriptions).toEqual([otherId])
    expect(wrapper.get('h1').text()).toBe('completed')
  })
})
