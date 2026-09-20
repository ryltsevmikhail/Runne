import { flushPromises } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import type { TaskRunTimeline } from '@/entities/task-run'
import { currentLocale } from '@/shared/i18n'

import {
  committedEntry,
  deferred,
  liveTimeline,
  mountTaskRunPage,
  otherTaskRunId,
  taskRunId,
  timelineWith,
  type SubscribeTaskRunFake,
  type TaskRunPageHarness,
} from './task-run-page-test-support'

describe('TaskRun page recovery projection', () => {
  it('keeps the display stable when duplicate and stale same-content frames arrive', async () => {
    let deliver: ((value: TaskRunTimeline) => void) | undefined
    const subscribe: SubscribeTaskRunFake = async (_id, _initial, onTimeline) => {
      deliver = onTimeline
      return { unsubscribe: async () => {}, resync: async () => liveTimeline }
    }
    const { wrapper } = await mountTaskRunPage({ subscribeTaskRun: subscribe })
    // Страница применяет любой кадр без проверки ревизии, поэтому сценарий
    // покрывает только кадры с идентичным контентом (тот же state/entries).
    deliver?.(liveTimeline)
    deliver?.({ ...liveTimeline, projectionRevision: 0 })
    await flushPromises()
    expect(wrapper.get('h1').text()).toBe('running')
    expect(wrapper.text()).not.toContain('Connection to the task stream was lost.')
    expect(wrapper.text()).not.toContain('The last operation failed')
    expect(wrapper.find('[data-task-run-action="cancel"]').exists()).toBe(true)
  })

  it('does not leak in-flight data from the previous task after navigation', async () => {
    const firstLoad = deferred<TaskRunTimeline>()
    const { wrapper, navigate } = await mountTaskRunPage({
      loadTaskRun: async (id) => id === taskRunId
        ? firstLoad.promise
        : { ...liveTimeline, taskRunId: otherTaskRunId, state: 'succeeded', entries: [{ ...committedEntry, kind: 'completed' as const }] },
    })
    await navigate(otherTaskRunId)
    firstLoad.resolve(liveTimeline)
    await flushPromises()
    expect(wrapper.get('h1').text()).toBe('succeeded')
    expect(wrapper.text()).toContain('completed')
    expect(wrapper.text()).not.toContain('running')
    expect(wrapper.text()).not.toContain('attempt started')
  })

  it('marks the confirmed snapshot stale on disconnect and returns live after recovery', async () => {
    const { wrapper, runtime }: TaskRunPageHarness = await mountTaskRunPage()
    expect(wrapper.text()).not.toContain('Last confirmed snapshot')
    runtime.stale()
    await flushPromises()
    expect(wrapper.text()).toContain('Connection to the task stream was lost.')
    const stale = wrapper.get('[role="status"]')
    expect(stale.text()).toContain('revision 1')
    expect(stale.text()).toContain('stream 1')
    expect(stale.text()).not.toContain('event at')
    expect(stale.text()).toContain('data may be outdated')
    expect(wrapper.find('[data-task-run-action="cancel"]').exists()).toBe(false)
    expect(wrapper.find('button').exists()).toBe(false)
    runtime.live()
    await flushPromises()
    expect(wrapper.text()).not.toContain('Connection to the task stream was lost.')
    expect(wrapper.text()).not.toContain('Last confirmed snapshot')
    expect(wrapper.find('[data-task-run-action="cancel"]').exists()).toBe(true)
  })

  it('does not auto-retry after a subscribe failure until the runtime returns live', async () => {
    let loads = 0
    let subscriptions = 0
    const load = async () => { loads += 1; return { ...liveTimeline, state: 'succeeded' as const } }
    const subscribe: SubscribeTaskRunFake = async (_id, _initial, onTimeline) => {
      subscriptions += 1
      onTimeline({ ...liveTimeline, state: 'succeeded', recovery: 'live' })
      throw new Error('native subscription rejected')
    }
    const { wrapper, runtime, settle } = await mountTaskRunPage({ loadTaskRun: load, subscribeTaskRun: subscribe })
    expect(wrapper.text()).toContain('Connection to the task stream was lost.')
    expect(wrapper.find('[role="status"]').exists()).toBe(true)
    expect(wrapper.find('button').exists()).toBe(false)
    expect(loads).toBe(1)
    expect(subscriptions).toBe(1)
    await settle()
    expect(loads).toBe(1)
    expect(subscriptions).toBe(1)
    // Восстановление live возможно только через watch [taskRunId, runtimeStatus]:
    // переход статуса stale→live пересоздаёт подписку ровно один раз.
    runtime.stale()
    await flushPromises()
    runtime.live()
    await flushPromises()
    expect(loads).toBe(2)
    expect(subscriptions).toBe(2)
    await settle()
    expect(subscriptions).toBe(2)
  })

  it('releases the subscription once on unmount and drops later deliveries', async () => {
    let deliver: ((value: TaskRunTimeline) => void) | undefined
    let unsubscribes = 0
    let loads = 0
    const subscribe: SubscribeTaskRunFake = async (_id, _initial, onTimeline) => {
      deliver = onTimeline
      return { unsubscribe: async () => { unsubscribes += 1 }, resync: async () => liveTimeline }
    }
    const { wrapper } = await mountTaskRunPage({ loadTaskRun: async () => { loads += 1; return liveTimeline }, subscribeTaskRun: subscribe })
    const mountedElement = wrapper.element
    wrapper.unmount()
    await flushPromises()
    expect(unsubscribes).toBe(1)
    deliver?.({ ...liveTimeline, projectionRevision: 2, streamVersion: 2, entries: [...liveTimeline.entries, { ...committedEntry, sequence: 2, kind: 'completed' as const }] })
    await flushPromises()
    expect(unsubscribes).toBe(1)
    expect(loads).toBe(1)
    expect(mountedElement.isConnected).toBe(false)
  })

  it('distinguishes loading from empty runtime and from an entry-less snapshot', async () => {
    const pending = deferred<TaskRunTimeline>()
    const loading = await mountTaskRunPage({ loadTaskRun: () => pending.promise })
    expect(loading.wrapper.get('section[aria-live="polite"]').text()).toBe('Loading task run…')
    expect(loading.wrapper.find('h1').exists()).toBe(false)
    expect(loading.wrapper.find('button').exists()).toBe(false)
    expect(loading.wrapper.find('[role="status"]').exists()).toBe(false)

    const emptyRuntime = await mountTaskRunPage({ initialStatus: 'empty' })
    expect(emptyRuntime.wrapper.get('section[role="status"]').text()).toContain('Runtime is not configured')
    expect(emptyRuntime.wrapper.text()).not.toContain('Loading')

    const entryless = await mountTaskRunPage({ loadTaskRun: async () => ({ ...liveTimeline, entries: [] }) })
    expect(entryless.wrapper.text()).toContain('No canonical events have been recorded.')
    expect(entryless.wrapper.get('[role="status"]').text()).toContain('no recorded events')
    expect(entryless.wrapper.find('h1').exists()).toBe(true)
  })

  it('keeps the localized unavailable placeholder when the initial load fails', async () => {
    const previousLocale = currentLocale.value
    currentLocale.value = 'ru'
    try {
      const { wrapper } = await mountTaskRunPage({ loadTaskRun: async () => { throw new Error('unavailable') } })
      expect(wrapper.text()).toContain('TaskRun недоступен.')
      expect(wrapper.find('h1').exists()).toBe(false)
    } finally {
      currentLocale.value = previousLocale
    }
  })

  it('treats every non-live recovery as read-only without action buttons', async () => {
    for (const recovery of ['reconnecting', 'revoked', 'fatal', 'incompatible'] as const) {
      const { wrapper } = await mountTaskRunPage({ loadTaskRun: async () => timelineWith(recovery) })
      expect(wrapper.find('button').exists()).toBe(false)
      expect(wrapper.find('[role="status"]').exists()).toBe(true)
    }
  })

  it('shows the waiting placeholder while the runtime session has not gone live', async () => {
    const { wrapper } = await mountTaskRunPage({ initialStatus: 'stale' })
    expect(wrapper.get('section[aria-live="polite"]').text()).toBe('Waiting for the runtime session…')
    expect(wrapper.find('h1').exists()).toBe(false)
    expect(wrapper.find('button').exists()).toBe(false)
  })

  it('localizes the waiting placeholder for the ru locale', async () => {
    const previousLocale = currentLocale.value
    currentLocale.value = 'ru'
    try {
      const { wrapper } = await mountTaskRunPage({ initialStatus: 'stale' })
      expect(wrapper.get('section[aria-live="polite"]').text()).toBe('Ожидание runtime-сессии…')
      expect(wrapper.text()).not.toContain('Waiting for the runtime session')
    } finally {
      currentLocale.value = previousLocale
    }
  })
})
