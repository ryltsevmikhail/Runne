import { describe, expect, it } from 'vitest'

import { openProjectConversation, sendProjectMessage } from './conversations'

const snapshot = {
  conversationId: '018f2e3a-7000-7000-8000-000000000101',
  streamVersion: 3,
  messages: [
    {
      messageId: '018f2e3a-7000-7000-8000-000000000102',
      role: 'user',
      taskRunId: '018f2e3a-7000-7000-8000-000000000103',
      attemptId: '018f2e3a-7000-7000-8000-000000000104',
      text: 'hello',
      committedAt: 1_753_800_000_001,
    },
    {
      messageId: '018f2e3a-7000-7000-8000-000000000105',
      role: 'assistant',
      taskRunId: '018f2e3a-7000-7000-8000-000000000103',
      attemptId: '018f2e3a-7000-7000-8000-000000000104',
      text: 'GOCODE local response: hello',
      committedAt: 1_753_800_000_002,
    },
  ],
} as const

describe('conversation IPC adapter', () => {
  it('loads a strict sanitized timeline for one local project', async () => {
    const calls: Array<[string, Record<string, unknown> | undefined]> = []

    const value = await openProjectConversation(7, async (command, args) => {
      calls.push([command, args])
      return snapshot
    })

    expect(value).toEqual(snapshot)
    expect(calls).toEqual([['open_project_conversation', { projectId: 7 }]])
  })

  it('sends only project identity and bounded text through typed IPC', async () => {
    const calls: Array<[string, Record<string, unknown> | undefined]> = []

    const value = await sendProjectMessage(7, 'hello', async (command, args) => {
      calls.push([command, args])
      return snapshot
    })

    expect(value.messages.at(1)?.text).toBe('GOCODE local response: hello')
    expect(calls).toEqual([
      ['send_project_message', { projectId: 7, text: 'hello' }],
    ])
  })

  it('rejects unknown fields, roles, and malformed canonical identities', async () => {
    await expect(
      openProjectConversation(7, async () => ({
        ...snapshot,
        token: 'must-not-cross-ipc',
      })),
    ).rejects.toThrow('Invalid conversation response')

    await expect(
      openProjectConversation(7, async () => ({
        ...snapshot,
        messages: [{ ...snapshot.messages[0], role: 'tool' }],
      })),
    ).rejects.toThrow('Invalid conversation response')

    await expect(
      openProjectConversation(7, async () => ({
        ...snapshot,
        conversationId: 'not-a-uuid',
      })),
    ).rejects.toThrow('Invalid conversation response')
  })
})
