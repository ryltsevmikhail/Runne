export const snapshot = {
  conversationId: '018f2e3a-7000-7000-8000-000000000101',
  projectionRevision: 3,
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
  recovery: 'live',
} as const

export const update = {
  kind: 'update',
  conversationId: snapshot.conversationId,
  projectionRevision: 4,
  streamVersion: 4,
  message: {
    messageId: '018f2e3a-7000-7000-8000-000000000106',
    role: 'assistant',
    taskRunId: '018f2e3a-7000-7000-8000-000000000103',
    attemptId: '018f2e3a-7000-7000-8000-000000000104',
    text: 'next',
    committedAt: 1_753_800_000_003,
  },
  recovery: 'live',
} as const
