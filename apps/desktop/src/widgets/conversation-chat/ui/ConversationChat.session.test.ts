import { flushPromises, mount } from '@vue/test-utils'
import { defineComponent, h, shallowRef, type Ref } from 'vue'
import { describe, expect, it, vi } from 'vitest'

import {
  provideRuntimeSession,
  type RuntimeSessionContext,
  type RuntimeSessionSnapshot,
} from '@/app/providers/runtime-session'
import type { ConversationSnapshot } from '@/entities/conversation'
import { workspaceId } from '@/entities/conversation/api/conversations.test-support'

import ConversationChat from './ConversationChat.vue'

const empty = {
  conversationId: '018f2e3a-7000-7000-8000-000000000111',
  projectionRevision: 1,
  streamVersion: 1,
  messages: [],
  recovery: 'live',
} as const

describe('conversation chat session integration', () => {
  it('reuses the proven session context without its own runtime handshake', async () => {
    const connectSpy = vi.fn(async () => {
      throw new Error('raw connect must not run')
    })
    const sessionSnapshot = shallowRef<RuntimeSessionSnapshot>({
      runtime: 'live',
      status: 'live',
      canMutate: true,
    })
    const context: RuntimeSessionContext = {
      snapshot: sessionSnapshot as Readonly<Ref<RuntimeSessionSnapshot>>,
      connect: async () => sessionSnapshot.value,
      retry: async () => sessionSnapshot.value,
      close: async () => {},
      observeBootstrap: () => sessionSnapshot.value,
      sessionTicket: () => 0,
      ticketFenced: () => false,
    }
    const Harness = defineComponent({
      setup() {
        provideRuntimeSession(context)
        return () => h(ConversationChat, {
          workspaceId,
          connect: connectSpy,
          openConversation: async (): Promise<ConversationSnapshot> => ({
            ...empty,
            messages: [{
              messageId: '018f2e3a-7000-7000-8000-000000000112',
              role: 'assistant' as const,
              taskRunId: '018f2e3a-7000-7000-8000-000000000113',
              attemptId: '018f2e3a-7000-7000-8000-000000000114',
              text: 'hello',
              committedAt: 1_753_800_000_001,
            }],
          }),
          subscribeConversation: async () => ({
            sendMessage: async () => empty,
            resync: async () => empty,
            unsubscribe: async () => {},
          }),
        })
      },
    })
    const wrapper = mount(Harness)
    await flushPromises()
    expect(wrapper.get('[data-message-role]').text()).toContain('hello')

    // Read-only window closes: the chat reloads through the proven session
    // without ever invoking a raw runtime connect.
    sessionSnapshot.value = { runtime: 'live', status: 'stale', canMutate: false }
    await flushPromises()
    sessionSnapshot.value = { runtime: 'live', status: 'live', canMutate: true }
    await flushPromises()
    expect(connectSpy).not.toHaveBeenCalled()
  })
})
