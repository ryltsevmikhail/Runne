import { describe, expect, it } from 'vitest'

import type {
  ConversationSnapshot,
  ConversationTimelineUpdate,
} from './timeline'
import {
  createConversationTimeline,
  reduceConversationTimeline,
} from './timeline'

const firstMessage = {
  messageId: '018f2e3a-7000-7000-8000-000000000202',
  role: 'user',
  taskRunId: '018f2e3a-7000-7000-8000-000000000203',
  attemptId: '018f2e3a-7000-7000-8000-000000000204',
  text: 'hello',
  committedAt: 1_753_800_000_001,
} as const

const initial: ConversationSnapshot = {
  conversationId: '018f2e3a-7000-7000-8000-000000000201',
  projectionRevision: 3,
  streamVersion: 3,
  messages: [firstMessage],
  recovery: 'live',
}

function update(
  overrides: Partial<ConversationTimelineUpdate> = {},
): ConversationTimelineUpdate {
  return {
    kind: 'update',
    conversationId: initial.conversationId,
    projectionRevision: 4,
    streamVersion: 4,
    message: {
      messageId: '018f2e3a-7000-7000-8000-000000000205',
      role: 'assistant',
      taskRunId: firstMessage.taskRunId,
      attemptId: firstMessage.attemptId,
      text: 'response',
      committedAt: 1_753_800_000_002,
    },
    recovery: 'live',
    ...overrides,
  }
}

describe('conversation timeline reducer', () => {
  it('accepts only the next revision and deduplicates an exact replay', () => {
    const current = createConversationTimeline(initial)
    const applied = reduceConversationTimeline(current, update())
    expect(applied.kind).toBe('applied')
    expect(applied.timeline.snapshot.projectionRevision).toBe(4)
    expect(applied.timeline.snapshot.messages).toHaveLength(2)

    const duplicate = reduceConversationTimeline(applied.timeline, update())
    expect(duplicate.kind).toBe('duplicate')
    expect(duplicate.timeline.snapshot.messages).toHaveLength(2)
  })

  it('deduplicates an existing message ID only when its sanitized bytes match', () => {
    const current = createConversationTimeline(initial)
    const exact = reduceConversationTimeline(current, update({
      message: firstMessage,
    }))
    expect(exact.kind).toBe('applied')
    expect(exact.timeline.snapshot.messages).toHaveLength(1)

    const changed = reduceConversationTimeline(
      createConversationTimeline(initial),
      update({
        message: { ...firstMessage, text: 'changed' },
      }),
    )
    expect(changed.kind).toBe('incompatible')
  })

  it('stops for a revision gap, regression, or changed duplicate revision', () => {
    const current = createConversationTimeline(initial)
    expect(reduceConversationTimeline(current, update({
      projectionRevision: 5,
    })).kind).toBe('gap')
    expect(reduceConversationTimeline(current, update({
      projectionRevision: 2,
    })).kind).toBe('incompatible')
    expect(reduceConversationTimeline(current, update({
      projectionRevision: 3,
      streamVersion: 99,
    })).kind).toBe('incompatible')
  })

  it('rejects same-revision events after a full snapshot without a canonical signature', () => {
    const current = createConversationTimeline(initial)

    expect(reduceConversationTimeline(current, update({
      projectionRevision: initial.projectionRevision,
      streamVersion: initial.streamVersion,
      message: firstMessage,
    })).kind).toBe('incompatible')
    expect(reduceConversationTimeline(current, update({
      projectionRevision: initial.projectionRevision,
      streamVersion: initial.streamVersion,
      message: null,
    })).kind).toBe('incompatible')
  })

  it('keeps the last confirmed messages while entering reconnecting', () => {
    const current = createConversationTimeline(initial)
    const result = reduceConversationTimeline(current, update({
      message: null,
      recovery: 'reconnecting',
    }))

    expect(result.kind).toBe('applied')
    expect(result.timeline.snapshot.messages).toEqual([firstMessage])
    expect(result.timeline.snapshot.recovery).toBe('reconnecting')
  })
})
