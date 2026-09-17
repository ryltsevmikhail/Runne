import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'

import type { ConversationSnapshot } from '@/entities/conversation'
import { workspaceId } from '@/entities/conversation/api/conversations.test-support'
import ConversationChat from './ConversationChat.vue'

const empty: ConversationSnapshot = {
  conversationId: '018f2e3a-7000-7000-8000-000000000111',
  projectionRevision: 1,
  streamVersion: 1,
  messages: [],
  recovery: 'live',
}

describe('conversation chat draft preservation', () => {
  it('keeps draft and disables compose/send/resync during a transient status', async () => {
    const sendMessage = vi.fn(async () => empty)
    const resync = vi.fn(async () => empty)
    const wrapper = mount(ConversationChat, {
      props: {
        workspaceId,
        disabled: false,
        connect: async () => 'live',
        openConversation: async () => ({ ...empty, recovery: 'resync_required' }),
        subscribeConversation: async () => ({ sendMessage, resync, unsubscribe: async () => {} }),
      },
    })
    await flushPromises()
    await wrapper.get('textarea').setValue('draft survives')
    await wrapper.setProps({ disabled: true })

    expect(wrapper.get('textarea').element.value).toBe('draft survives')
    expect(wrapper.get('textarea').attributes('disabled')).toBeDefined()
    expect(wrapper.get('button[type="submit"]').attributes('disabled')).toBeDefined()
    expect(wrapper.get('button[name="resync-conversation"]').attributes('disabled')).toBeDefined()
    await wrapper.get('form').trigger('submit')
    await wrapper.get('button[name="resync-conversation"]').trigger('click')
    expect(sendMessage).not.toHaveBeenCalled()
    expect(resync).not.toHaveBeenCalled()

    await wrapper.setProps({ disabled: false })
    expect(wrapper.get('textarea').element.value).toBe('draft survives')
    expect(sendMessage).not.toHaveBeenCalled()
  })

  it('does not persist a draft during mount, transient status, or unmount', async () => {
    const setItem = vi.spyOn(Storage.prototype, 'setItem')
    const wrapper = mount(ConversationChat, { props: { workspaceId, disabled: true } })
    await wrapper.get('textarea').setValue('ephemeral only')
    wrapper.unmount()
    expect(setItem).not.toHaveBeenCalled()
    setItem.mockRestore()
  })
})
