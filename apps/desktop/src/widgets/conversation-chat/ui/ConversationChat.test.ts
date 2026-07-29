import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import type { ConversationSnapshot } from '@/entities/conversation'

import ConversationChat from './ConversationChat.vue'

const empty: ConversationSnapshot = {
  conversationId: '018f2e3a-7000-7000-8000-000000000111',
  streamVersion: 1,
  messages: [],
}

const generated: ConversationSnapshot = {
  conversationId: empty.conversationId,
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
      text: 'GOCODE local response: hello',
      committedAt: 1_753_800_000_002,
    },
  ],
}

describe('conversation chat widget', () => {
  it('connects, opens the project conversation, and renders durable messages', async () => {
    const calls: string[] = []
    const wrapper = mount(ConversationChat, {
      props: {
        projectId: 7,
        connect: async () => {
          calls.push('connect')
          return 'live'
        },
        openConversation: async (projectId) => {
          calls.push(`open:${projectId}`)
          return generated
        },
        sendMessage: async () => generated,
      },
    })
    await flushPromises()

    expect(calls).toEqual(['connect', 'open:7'])
    expect(wrapper.get('[aria-label="Conversation messages"]').text()).toContain('hello')
    expect(wrapper.text()).toContain('GOCODE local response: hello')
    expect(wrapper.text()).toContain('Runtime live')
  })

  it('submits text once, clears the composer, and renders the returned snapshot', async () => {
    const sends: Array<[number, string]> = []
    const wrapper = mount(ConversationChat, {
      props: {
        projectId: 7,
        connect: async () => 'live',
        openConversation: async () => empty,
        sendMessage: async (projectId, text) => {
          sends.push([projectId, text])
          return generated
        },
      },
    })
    await flushPromises()

    await wrapper.get('textarea').setValue('hello')
    await wrapper.get('form').trigger('submit')
    await flushPromises()

    expect(sends).toEqual([[7, 'hello']])
    expect(wrapper.get('textarea').element.value).toBe('')
    expect(wrapper.findAll('[data-message-role]')).toHaveLength(2)
  })

  it('fails closed with a retry action when runtime connection is unavailable', async () => {
    let attempts = 0
    const wrapper = mount(ConversationChat, {
      props: {
        projectId: 7,
        connect: async () => {
          attempts += 1
          throw new Error('unavailable')
        },
        openConversation: async () => empty,
        sendMessage: async () => generated,
      },
    })
    await flushPromises()

    expect(wrapper.get('[role="alert"]').text()).toContain('Runtime unavailable')
    await wrapper.get('button').trigger('click')
    await flushPromises()
    expect(attempts).toBe(2)
  })
})
