import { flushPromises, mount } from '@vue/test-utils'
import { defineComponent, h } from 'vue'
import { describe, expect, it, vi } from 'vitest'

import {
  createRuntimeSessionContext,
  createRuntimeSessionController,
  provideRuntimeSession,
} from '@/app/providers/runtime-session'
import type { ConversationSnapshot } from '@/entities/conversation'
import TextChatPage from '@/pages/text-chat/ui/TextChatPage.vue'

const transport = vi.hoisted(() => ({
  open: vi.fn(),
  subscribe: vi.fn(),
}))

vi.mock('@/entities/conversation', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/entities/conversation')>()
  return {
    ...actual,
    openTextOnlyConversation: transport.open,
    subscribeTextOnlyConversation: transport.subscribe,
  }
})

const empty: ConversationSnapshot = {
  conversationId: '018f2e3a-7000-7000-8000-000000000111',
  projectionRevision: 1,
  streamVersion: 1,
  messages: [],
  recovery: 'live',
}

const bootstrap = (runtime: string) => ({ runtime })

describe('text chat runtime-session integration', () => {
  it('reopens text-only chat after fresh proof in either stream ordering', async () => {
    let releaseTransport!: (state: 'live') => void
    let holdTransport = false
    const controller = createRuntimeSessionController({
      connect: () => holdTransport
        ? new Promise(resolve => { releaseTransport = resolve })
        : Promise.resolve('live'),
      loadBootstrap: async () => bootstrap('live'),
    })
    const context = createRuntimeSessionContext(controller)
    await context.connect()
    const listeners: Array<(value: ConversationSnapshot) => void> = []
    let opens = 0
    transport.open.mockImplementation(async () => {
      opens += 1
      return { ...empty, projectionRevision: opens }
    })
    transport.subscribe.mockImplementation(async (
      _initial: ConversationSnapshot,
      onTimeline: (value: ConversationSnapshot) => void,
    ) => {
      listeners.push(onTimeline)
      return {
        sendMessage: async () => empty,
        resync: async () => empty,
        unsubscribe: async () => {},
      }
    })
    const Harness = defineComponent({
      setup() {
        provideRuntimeSession(context)
        return () => h(TextChatPage)
      },
    })
    const wrapper = mount(Harness)
    await flushPromises()
    expect(opens).toBe(1)
    expect(transport.open.mock.calls[0]).toHaveLength(0)
    expect(transport.subscribe.mock.calls[0]).toHaveLength(2)

    // Renewal first revokes mutation; the old stream may report its drop
    // before the controller finishes a held transport reconnect.
    holdTransport = true
    context.observeBootstrap(bootstrap('reconnecting'))
    listeners[0]?.({ ...empty, recovery: 'reconnecting' })
    await wrapper.vm.$nextTick()
    expect((wrapper.find('textarea').element as HTMLTextAreaElement).disabled).toBe(true)
    expect(opens).toBe(1)

    await vi.waitFor(() => expect(releaseTransport).toBeTypeOf('function'))
    expect(opens).toBe(1)
    holdTransport = false
    releaseTransport('live')
    await vi.waitFor(() => expect(controller.snapshot().status).toBe('live'))
    // App's subsequent bootstrap poll publishes fresh state after the
    // authenticated connect. The stale retained conversation is reopened.
    context.observeBootstrap(bootstrap('live'))
    await vi.waitFor(() => expect(opens).toBe(2))
    expect((wrapper.find('textarea').element as HTMLTextAreaElement).disabled).toBe(false)

    // In the opposite order, a stream drop arrives after fresh runtime proof.
    listeners[1]?.({ ...empty, recovery: 'reconnecting' })
    await vi.waitFor(() => expect(opens).toBe(3))
    expect(transport.open.mock.calls.every(call => call.length === 0)).toBe(true)
    expect(wrapper.text()).toContain('Project files and workspace context are not shared.')

    // A terminal session stays latched when a later bootstrap says live.
    context.observeBootstrap(bootstrap('revoked'))
    context.observeBootstrap(bootstrap('live'))
    await flushPromises()
    expect(opens).toBe(3)
  })
})
