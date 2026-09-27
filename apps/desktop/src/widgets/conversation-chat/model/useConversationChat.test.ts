import { mount } from '@vue/test-utils'
import { defineComponent, reactive } from 'vue'
import { describe, expect, it, vi } from 'vitest'

import type { ConversationSnapshot, ConversationTimelineListener } from '@/entities/conversation'
import type { RuntimeConnectionState } from '@/shared/api/platform/bootstrap'
import { useConversationChat, type ConversationChatOptions } from './useConversationChat'

const WORKSPACE = '01890e00-0000-7000-8000-000000000002'

function snapshot(recovery: ConversationSnapshot['recovery']): ConversationSnapshot {
  return {
    conversationId: '01890e00-0000-7000-9000-000000000009',
    projectionRevision: 1,
    streamVersion: 1,
    messages: [],
    recovery,
  }
}

function mountChat(
  options: ConversationChatOptions,
  sessionConnect?: (allowRetry: boolean) => Promise<RuntimeConnectionState>,
  sessionReady?: () => boolean,
) {
  const Component = defineComponent({
    setup() {
      const chat = useConversationChat(options, sessionConnect, sessionReady)
      return { chat }
    },
    template: '<div />',
  })
  return mount(Component)
}

describe('conversation chat recovery projection', () => {
  it('coalesces reloads requested while an open is in flight', async () => {
    let releaseOpen!: (value: ConversationSnapshot) => void
    const openConversation = vi.fn((): Promise<ConversationSnapshot> => new Promise(resolve => {
      releaseOpen = resolve
    }))
    const options: ConversationChatOptions = reactive({
      workspaceId: WORKSPACE,
      disabled: false,
      connect: async () => 'live' as const,
      openConversation,
      subscribeConversation: async () => ({
        sendMessage: async () => snapshot('live'),
        resync: async () => snapshot('live'),
        unsubscribe: async () => {},
      }),
    })
    const sessionConnect = vi.fn(async () => 'live' as const)
    mountChat(options, sessionConnect)
    await Promise.resolve()
    await Promise.resolve()
    expect(openConversation).toHaveBeenCalledTimes(1)

    // A read-only window opens and closes while the open is in flight: the
    // reload must coalesce into one, not stack.
    options.disabled = true
    await Promise.resolve()
    await Promise.resolve()
    options.disabled = false
    await Promise.resolve()
    await Promise.resolve()
    expect(openConversation).toHaveBeenCalledTimes(1)

    releaseOpen(snapshot('live'))
    await Promise.resolve()
    await Promise.resolve()
    await Promise.resolve()
    await Promise.resolve()
    expect(openConversation).toHaveBeenCalledTimes(2)
    // The mount and coalesced reload both revalidate the proven session.
    expect(sessionConnect).toHaveBeenCalledTimes(2)
    expect(sessionConnect).toHaveBeenCalledWith(false)
    await new Promise(resolve => setTimeout(resolve, 50))
    expect(openConversation).toHaveBeenCalledTimes(2)
  })

  it('resubscribes a dropped conversation subscription with a bounded reload', async () => {
    let failSubscribe = true
    let attempts = 0
    let push: ((value: ConversationSnapshot) => void) | undefined
    const options: ConversationChatOptions = reactive({
      workspaceId: WORKSPACE,
      disabled: false,
      connect: async () => 'live' as const,
      openConversation: async () => snapshot('live'),
      subscribeConversation: async (
        _id: string,
        _initial: ConversationSnapshot,
        onTimeline: ConversationTimelineListener,
      ) => {
        attempts += 1
        push = onTimeline
        if (failSubscribe) throw new Error('subscription unavailable')
        return {
          sendMessage: async () => snapshot('live'),
          resync: async () => snapshot('live'),
          unsubscribe: async () => {},
        }
      },
    })
    const sessionConnect = vi.fn(async () => 'live' as const)
    const wrapper = mountChat(options, sessionConnect)
    await vi.waitFor(() => expect(attempts).toBeGreaterThanOrEqual(2))

    // Recovery reloads stay bounded: two consecutive failed attempts, then
    // the composable stops resubscribing until the runtime recovers.
    await vi.waitFor(() => expect(attempts).toBeGreaterThanOrEqual(3))
    await new Promise(resolve => setTimeout(resolve, 100))
    const afterBounded = attempts
    await new Promise(resolve => setTimeout(resolve, 100))
    expect(attempts).toBe(afterBounded)

    // A live subscription refills the bounded budget: after one recovery the
    // composable survives another drop instead of staying dead until remount.
    failSubscribe = false
    options.disabled = true
    await Promise.resolve()
    options.disabled = false
    await vi.waitFor(() => expect(attempts).toBeGreaterThanOrEqual(4))
    await vi.waitFor(() => expect(wrapper.vm.chat.snapshot.value?.recovery).toBe('live'))
    failSubscribe = true
    push?.(snapshot('reconnecting'))
    await vi.waitFor(() => expect(attempts).toBeGreaterThanOrEqual(5))
    // The refilled budget is bounded again: the count stops growing.
    await new Promise(resolve => setTimeout(resolve, 100))
    const afterRefilled = attempts
    await new Promise(resolve => setTimeout(resolve, 100))
    expect(attempts).toBe(afterRefilled)
  })

  it('rearms one bounded recovery cycle only after a fresh session-ready edge', async () => {
    let failSubscribe = true
    let attempts = 0
    const state = reactive({ ready: true })
    const options: ConversationChatOptions = reactive({
      workspaceId: WORKSPACE,
      openConversation: async () => snapshot('live'),
      subscribeConversation: async () => {
        attempts += 1
        if (failSubscribe) throw new Error('subscription unavailable')
        return {
          sendMessage: async () => snapshot('live'),
          resync: async () => snapshot('live'),
          unsubscribe: async () => {},
        }
      },
    })
    const wrapper = mountChat(options, async () => 'live', () => state.ready)
    await vi.waitFor(() => expect(attempts).toBe(3))
    await new Promise(resolve => setTimeout(resolve, 50))
    expect(attempts).toBe(3)

    // A newly proven runtime session permits one fresh bounded cycle; stable
    // live polls alone do not repeatedly reset its failure budget.
    failSubscribe = false
    state.ready = false
    await Promise.resolve()
    state.ready = true
    await vi.waitFor(() => expect(attempts).toBe(4))
    await vi.waitFor(() => expect(wrapper.vm.chat.snapshot.value?.recovery).toBe('live'))
    await new Promise(resolve => setTimeout(resolve, 50))
    expect(attempts).toBe(4)
  })

  it('does not clear a conversation resync requirement on a runtime edge', async () => {
    const state = reactive({ ready: true })
    const openConversation = vi.fn(async () => snapshot('resync_required'))
    const options: ConversationChatOptions = reactive({
      workspaceId: WORKSPACE,
      openConversation,
      subscribeConversation: async () => ({
        sendMessage: async () => snapshot('live'),
        resync: async () => snapshot('live'),
        unsubscribe: async () => {},
      }),
    })
    const wrapper = mountChat(options, async () => 'live', () => state.ready)
    await vi.waitFor(() => expect(wrapper.vm.chat.snapshot.value?.recovery).toBe('resync_required'))

    state.ready = false
    await Promise.resolve()
    state.ready = true
    await new Promise(resolve => setTimeout(resolve, 50))

    expect(openConversation).toHaveBeenCalledTimes(1)
    expect(wrapper.vm.chat.snapshot.value?.recovery).toBe('resync_required')
  })

  it('reloads the conversation when the session becomes mutable again', async () => {
    let listener: ((value: ConversationSnapshot) => void) | undefined
    const openConversation = vi.fn(async (): Promise<ConversationSnapshot> => snapshot('live'))
    const connect = vi.fn(async (): Promise<RuntimeConnectionState> => 'live')
    const subscribeConversation = vi.fn(
      async (_id: string, _initial: ConversationSnapshot, onTimeline: ConversationTimelineListener) => {
        listener = onTimeline
        return {
          sendMessage: async () => snapshot('live'),
          resync: async () => snapshot('live'),
          unsubscribe: async () => {},
        }
      },
    )
    const options = reactive<ConversationChatOptions>({
      workspaceId: WORKSPACE,
      disabled: false,
      connect,
      openConversation,
      subscribeConversation,
    })
    const sessionConnect = vi.fn(() => Promise.resolve('live' as const))
    const wrapper = mountChat(options, sessionConnect)
    await Promise.resolve()
    await Promise.resolve()
    expect(openConversation).toHaveBeenCalledTimes(1)

    // A rotation window marks the retained snapshot reconnecting...
    listener?.(snapshot('reconnecting'))
    await Promise.resolve()
    expect(wrapper.vm.chat.snapshot.value?.recovery).toBe('reconnecting')

    // ...and the read-only gate closes and reopens with the session: the
    // reload reuses the proven session without a new handshake.
    options.disabled = true
    await Promise.resolve()
    options.disabled = false
    await vi.waitFor(() => expect(openConversation).toHaveBeenCalledTimes(2))
    // Recovery reloads verify the current session without retry rights.
    expect(sessionConnect).toHaveBeenCalledTimes(2)
    expect(sessionConnect).toHaveBeenCalledWith(false)
    await vi.waitFor(() => {
      expect(wrapper.vm.chat.snapshot.value?.recovery).toBe('live')
    })
    // The session connector is rechecked, while the raw handshake fallback
    // stays untouched and no automatic retry capability is requested.
    expect(connect).not.toHaveBeenCalled()
    expect(sessionConnect).toHaveBeenCalledWith(false)
  })
})
