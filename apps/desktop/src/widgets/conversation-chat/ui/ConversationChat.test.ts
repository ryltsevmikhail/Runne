import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'

import type {
  ConversationSession,
  ConversationSnapshot,
  ConversationTimelineListener,
} from '@/entities/conversation'
import { workspaceId } from '@/entities/conversation/api/conversations.test-support'
import { currentLocale } from '@/shared/i18n'

import ConversationChat from './ConversationChat.vue'

const empty: ConversationSnapshot = {
  conversationId: '018f2e3a-7000-7000-8000-000000000111',
  projectionRevision: 1,
  streamVersion: 1,
  messages: [],
  recovery: 'live',
}

const generated: ConversationSnapshot = {
  conversationId: empty.conversationId,
  projectionRevision: 3,
  streamVersion: 3,
  messages: [
    {
      messageId: '018f2e3a-7000-7000-8000-000000000112',
      role: 'user',
      taskRunId: '018f2e3a-7000-7000-8000-000000000113',
      attemptId: '018f2e3a-7000-7000-8000-000000000114',
      text: 'hello',
      committedAt: 1_753_800_000_001,
    },
    {
      messageId: '018f2e3a-7000-7000-8000-000000000115',
      role: 'assistant',
      taskRunId: '018f2e3a-7000-7000-8000-000000000113',
      attemptId: '018f2e3a-7000-7000-8000-000000000114',
      text: 'Runne local response: hello',
      committedAt: 1_753_800_000_002,
    },
  ],
  recovery: 'live',
}

function mockSession(
  sendMessage: ConversationSession['sendMessage'] = async () => generated,
  resync: ConversationSession['resync'] = async () => generated,
  unsubscribe = async () => undefined,
): ConversationSession {
  return {
    sendMessage,
    resync,
    unsubscribe,
  }
}

describe('conversation chat widget', () => {
  it('connects, opens the workspace conversation, and renders durable messages', async () => {
    const calls: string[] = []
    const wrapper = mount(ConversationChat, {
      props: {
        workspaceId,
        connect: async () => {
          calls.push('connect')
          return 'live'
        },
        openConversation: async (id) => {
          calls.push(`open:${id}`)
          return generated
        },
        subscribeConversation: async (id) => {
          calls.push(`subscribe:${id}`)
          return mockSession()
        },
      },
    })
    await flushPromises()

    expect(calls).toEqual(['connect', `open:${workspaceId}`, `subscribe:${workspaceId}`])
    expect(wrapper.get('[aria-label="Conversation messages"]').text()).toContain('hello')
    expect(wrapper.text()).toContain('Runne local response: hello')
    expect(wrapper.text()).toContain('Runtime live')
    expect(wrapper.get('.conversation-chat__header h2').text()).toBe('Coding agent')
    expect(wrapper.get('[aria-label="Conversation runtime status"]').text()).toBe('Runtime live')
    expect(wrapper.get('label').text()).toBe('Message')
    expect(wrapper.get('textarea')).toBeTruthy()
  })

  it('submits text once, clears the composer, and renders the returned snapshot', async () => {
    const sends: Array<[string, string]> = []
    const wrapper = mount(ConversationChat, {
      props: {
        workspaceId,
        connect: async () => 'live',
        openConversation: async () => empty,
        subscribeConversation: async (id, _initial, onTimeline) => {
          return mockSession(async (text) => {
            sends.push([id, text])
            onTimeline(generated)
            return generated
          })
        },
      },
    })
    await flushPromises()

    await wrapper.get('textarea').setValue('hello')
    await wrapper.get('form').trigger('submit')
    await flushPromises()

    expect(sends).toEqual([[workspaceId, 'hello']])
    expect(wrapper.get('textarea').element.value).toBe('')
    expect(wrapper.findAll('[data-message-role]')).toHaveLength(2)
  })

  it('fails closed with a retry action when runtime connection is unavailable', async () => {
    let attempts = 0
    const wrapper = mount(ConversationChat, {
      props: {
        workspaceId,
        connect: async () => {
          attempts += 1
          throw new Error('unavailable')
        },
        openConversation: async () => empty,
        subscribeConversation: async () => mockSession(),
      },
    })
    await flushPromises()

    expect(wrapper.get('[role="alert"]').text()).toContain('Runtime unavailable')
    await wrapper.get('button').trigger('click')
    await flushPromises()
    expect(attempts).toBe(2)
  })

  it('renders each message ID once across live and reconnect duplicates', async () => {
    let listener: ConversationTimelineListener | undefined
    const wrapper = mount(ConversationChat, {
      props: {
        workspaceId,
        connect: async () => 'live',
        openConversation: async () => generated,
        subscribeConversation: async (_workspaceId, _initial, onTimeline) => {
          listener = onTimeline
          return mockSession()
        },
      },
    })
    await flushPromises()

    listener?.(generated)
    listener?.({
      ...generated,
      projectionRevision: 4,
      streamVersion: 4,
      recovery: 'reconnecting',
    })
    await wrapper.vm.$nextTick()

    expect(wrapper.findAll('[data-message-role]')).toHaveLength(2)
    expect(new Set(
      wrapper.findAll('[data-message-id]').map(node => node.attributes('data-message-id')),
    ).size).toBe(2)
    expect(wrapper.text()).toContain('Reconnecting')
    expect(wrapper.get('textarea').attributes('disabled')).toBeDefined()
  })

  it('localizes recovery status through the owned catalog', async () => {
    const previousLocale = currentLocale.value
    currentLocale.value = 'ru'
    try {
      const wrapper = mount(ConversationChat, {
        props: {
          workspaceId,
          connect: async () => 'live',
          openConversation: async () => ({ ...generated, recovery: 'incompatible' }),
          subscribeConversation: async () => mockSession(),
        },
      })
      await flushPromises()
      expect(wrapper.text()).toContain('Версия runtime несовместима.')
    } finally {
      currentLocale.value = previousLocale
    }
  })

  it.each([
    ['incompatible', 'Runtime version is incompatible.'],
    ['revoked', 'Runtime access was revoked.'],
    ['resync_required', 'Conversation resync is required.'],
    ['fatal', 'Conversation recovery failed.'],
  ] as const)('renders %s recovery closed and disables sending', async (recovery, copy) => {
    const wrapper = mount(ConversationChat, {
      props: {
        workspaceId,
        connect: async () => 'live',
        openConversation: async () => ({ ...generated, recovery }),
        subscribeConversation: async () => mockSession(),
      },
    })
    await flushPromises()

    expect(wrapper.text()).toContain(copy)
    expect(wrapper.get('textarea').attributes('disabled')).toBeDefined()
    expect(wrapper.get('button[type="submit"]').attributes('disabled')).toBeDefined()
  })

  it('keeps the resync action available when explicit recovery fails', async () => {
    const resync = vi.fn(async () => {
      throw new Error('retention still unavailable')
    })
    const wrapper = mount(ConversationChat, {
      props: {
        workspaceId,
        connect: async () => 'live',
        openConversation: async () => ({ ...generated, recovery: 'resync_required' }),
        subscribeConversation: async () => mockSession(async () => generated, resync),
      },
    })
    await flushPromises()

    await wrapper.get('button[name="resync-conversation"]').trigger('click')
    await flushPromises()

    expect(resync).toHaveBeenCalledOnce()
    expect(wrapper.text()).toContain('Conversation resync is required.')
    expect(wrapper.get('button[name="resync-conversation"]').attributes('disabled')).toBeUndefined()
    expect(wrapper.get('textarea').attributes('disabled')).toBeDefined()
  })

  it('unsubscribes on unmount after the subscription has been installed', async () => {
    const unsubscribe = vi.fn(async () => undefined)
    const wrapper = mount(ConversationChat, {
      props: {
        workspaceId,
        connect: async () => 'live',
        openConversation: async () => generated,
        subscribeConversation: async () => mockSession(
          async () => generated,
          async () => generated,
          unsubscribe,
        ),
      },
    })
    await flushPromises()

    wrapper.unmount()
    await flushPromises()
    expect(unsubscribe).toHaveBeenCalledOnce()
  })

  it('preserves confirmed messages read-only when sending loses the runtime', async () => {
    const wrapper = mount(ConversationChat, {
      props: {
        workspaceId,
        connect: async () => 'live',
        openConversation: async () => generated,
        subscribeConversation: async () => mockSession(async () => {
          throw new Error('runtime unavailable')
        }),
      },
    })
    await flushPromises()

    await wrapper.get('textarea').setValue('next')
    await wrapper.get('form').trigger('submit')
    await flushPromises()

    expect(wrapper.findAll('[data-message-role]')).toHaveLength(2)
    expect(wrapper.text()).toContain('Reconnecting')
    expect(wrapper.get('textarea').attributes('disabled')).toBeDefined()
  })
  it('never renders an unknown channel field supplied below the widget boundary', async () => {
    let listener: ConversationTimelineListener | undefined
    const wrapper = mount(ConversationChat, {
      props: {
        workspaceId,
        connect: async () => 'live',
        openConversation: async () => generated,
        subscribeConversation: async (_workspaceId, _initial, onTimeline) => {
          listener = onTimeline
          return mockSession()
        },
      },
    })
    await flushPromises()

    listener?.({
      ...generated,
      recovery: 'incompatible',
      secretCursor: 'must-not-render',
    } as ConversationSnapshot)
    await wrapper.vm.$nextTick()

    expect(wrapper.html()).not.toContain('secretCursor')
  })
})
