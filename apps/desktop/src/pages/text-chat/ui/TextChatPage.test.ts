import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import TextChatPage from './TextChatPage.vue'

describe('TextChatPage', () => {
  it('renders a separate text-only chat and explains the context boundary', () => {
    const wrapper = mount(TextChatPage, {
      global: {
        stubs: {
          ConversationChat: {
            template: '<div data-test="conversation-chat" />',
          },
        },
      },
    })

    expect(wrapper.find('[data-test="conversation-chat"]').exists()).toBe(true)
    expect(wrapper.text()).toContain('Project files and workspace context are not shared.')
  })
})
