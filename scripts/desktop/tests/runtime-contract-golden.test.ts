import { describe, expect, it } from 'vitest'

import {
  golden,
  object,
  parseReplayEvent,
  parseSseDelivery,
} from './runtime-contract-golden.support'
describe('runtime-owned exact contract goldens', () => {
  it('accepts generated Conversation, TaskRun and SSE examples', () => {
    expect(parseReplayEvent(golden('replay-conversation.json'))).toBeTruthy()
    expect(parseReplayEvent(golden('replay-taskrun.json'))).toBeTruthy()
    const sse = parseSseDelivery(golden('sse-delivery.json'))
    expect(object(sse.canonicalEvent)).not.toHaveProperty('cursor')
  })

  it('rejects extra replay fields', () => {
    const replay = object(golden('replay-conversation.json'))
    expect(() => parseReplayEvent({ ...replay, globalPosition: 42 })).toThrow('unexpected fields')
  })

  it('rejects unknown payload types', () => {
    const replay = object(golden('replay-conversation.json'))
    expect(() => parseReplayEvent({ ...replay, payload: { type: 'conversation.future' } })).toThrow('unknown payload type')
  })

  it('rejects malformed cursors', () => {
    const replay = object(golden('replay-conversation.json'))
    expect(() => parseReplayEvent({ ...replay, cursor: 'gocode-replay-cursor-v1.not-hex' })).toThrow('invalid cursor')
  })

  it('rejects UUID-form replay session identities', () => {
    const delivery = object(golden('sse-delivery.json'))
    expect(() => parseSseDelivery({
      ...delivery,
      replaySessionId: '018f2e3a-7000-7000-8000-000000000118',
    })).toThrow('invalid replay session')
  })

  it('rejects null required payload identities', () => {
    const replay = object(golden('replay-conversation.json'))
    expect(() => parseReplayEvent({
      ...replay,
      payload: { ...object(replay.payload), messageId: null },
    })).toThrow('invalid UUIDv7')
  })

  it('rejects invalid closed payload enums', () => {
    const replay = object(golden('replay-taskrun.json'))
    expect(() => parseReplayEvent({
      ...replay,
      eventType: 'taskRun.completed',
      payload: { outcome: 'future', reason: null, type: 'taskRun.completed' },
    })).toThrow('invalid outcome')
    expect(() => parseReplayEvent({
      ...replay,
      eventType: 'taskRun.loop.cycle.completed',
      payload: {
        attemptId: '018f2e3a-7000-7000-8000-000000000114',
        cycleId: '018f2e3a-7000-7000-8000-000000000119',
        disposition: 'future',
        type: 'taskRun.loop.cycle.completed',
      },
    })).toThrow('invalid disposition')
    expect(() => parseReplayEvent({
      ...replay,
      eventType: 'taskRun.loop.wake.accepted',
      payload: {
        cycleId: '018f2e3a-7000-7000-8000-000000000119',
        evidenceId: '018f2e3a-7000-7000-8000-000000000120',
        source: 'future',
        type: 'taskRun.loop.wake.accepted',
      },
    })).toThrow('invalid source')
  })

  it('rejects non-positive semantic sequence fields', () => {
    const replay = object(golden('replay-taskrun.json'))
    const delivery = {
      ...replay,
      eventType: 'taskRun.loop.cycle.started',
      payload: {
        attemptId: '018f2e3a-7000-7000-8000-000000000114',
        cycleId: '018f2e3a-7000-7000-8000-000000000119',
        parentCycleId: null,
        sequence: 0,
        type: 'taskRun.loop.cycle.started',
      },
    }
    expect(() => parseReplayEvent(delivery)).toThrow('invalid sequence')
    expect(() => parseReplayEvent({
      ...delivery,
      payload: { ...object(delivery.payload), sequence: -1 },
    })).toThrow('invalid sequence')
  })

  it('rejects event and payload type mismatch', () => {
    const replay = object(golden('replay-conversation.json'))
    expect(() => parseReplayEvent({
      ...replay,
      eventType: 'conversation.created',
    })).toThrow('event type mismatch')
  })
})
