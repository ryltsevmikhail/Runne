import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

type JsonObject = Record<string, unknown>

const UUID_V7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const CURSOR = /^gocode-replay-cursor-v1\.(?:[0-9a-f]{2})+$/
const LOWER_HEX_16 = /^[0-9a-f]{32}$/
const LOWER_HEX_32 = /^[0-9a-f]{64}$/

const payloadFields: Readonly<Record<string, readonly string[]>> = {
  'conversation.created': ['type', 'workspaceId'],
  'conversation.message.appended': ['attemptId', 'messageId', 'role', 'taskRunId', 'text', 'type'],
  'conversation.generation.failed': ['attemptId', 'reason', 'taskRunId', 'type'],
  'conversation.closed': ['type'],
  'taskRun.created': ['type'],
  'taskRun.queued': ['type'],
  'taskRun.admitted': ['type'],
  'taskRun.attempt.started': ['attemptId', 'type'],
  'taskRun.wait.started': ['type'],
  'taskRun.resumed': ['type'],
  'taskRun.retry.started': ['attemptId', 'type'],
  'taskRun.retry.completed': ['attemptId', 'type'],
  'taskRun.checkpoint.started': ['type'],
  'taskRun.checkpoint.committed': ['type'],
  'taskRun.cancellation.requested': ['type'],
  'taskRun.cancellation.completed': ['type'],
  'taskRun.completed': ['outcome', 'reason', 'type'],
  'taskRun.failed': ['reason', 'type'],
  'taskRun.budget.exhausted': ['type'],
  'taskRun.policy.denied': ['type'],
  'taskRun.reconciliation.started': ['type'],
  'taskRun.reconciliation.completed': ['type'],
  'taskRun.unrecoverable': ['type'],
  'taskRun.cancelled': ['type'],
  'taskRun.loop.cycle.started': ['attemptId', 'cycleId', 'parentCycleId', 'sequence', 'type'],
  'taskRun.context.committed': ['cycleId', 'manifestId', 'revision', 'type'],
  'taskRun.plan.committed': ['cycleId', 'expectedProposalIndexes', 'planId', 'revision', 'type'],
  'taskRun.step.outcome.recorded': ['cycleId', 'outcome', 'proposalIndex', 'stepId', 'type'],
  'taskRun.loop.cycle.completed': ['attemptId', 'cycleId', 'disposition', 'type'],
  'taskRun.next.cycle.created': ['attemptId', 'parentCycleId', 'sequence', 'successorCycleId', 'type'],
  'taskRun.retry.scheduled': ['abandonedCycleId', 'delayMillis', 'dueAtUnixMicros', 'newAttemptId', 'oldAttemptId', 'ordinal', 'type'],
  'taskRun.retry.attempt.activated': ['activatedAtUnixMicros', 'attemptId', 'ordinal', 'type'],
  'taskRun.recovery.resume.started': ['abandonedCycleId', 'newAttemptId', 'newGeneration', 'type'],
  'taskRun.loop.checkpoint.started': ['checkpointId', 'type'],
  'taskRun.loop.checkpoint.recorded': ['checkpointId', 'type'],
  'taskRun.loop.checkpoint.committed': ['checkpointId', 'type'],
  'taskRun.loop.wake.accepted': ['cycleId', 'evidenceId', 'source', 'type'],
}

function object(value: unknown): JsonObject {
  if (value === null || Array.isArray(value) || typeof value !== 'object') throw new Error('expected object')
  return value as JsonObject
}

function exactKeys(value: JsonObject, expected: readonly string[]): void {
  const actual = Object.keys(value).sort()
  if (JSON.stringify(actual) !== JSON.stringify([...expected].sort())) throw new Error('unexpected fields')
}

function string(value: unknown): string {
  if (typeof value !== 'string') throw new Error('expected string')
  return value
}

function uuid(value: unknown): string {
  const parsed = string(value)
  if (!UUID_V7.test(parsed)) throw new Error('invalid UUIDv7')
  return parsed
}

function cursor(value: unknown): string {
  const parsed = string(value)
  if (!CURSOR.test(parsed)) throw new Error('invalid cursor')
  return parsed
}

function parsePayload(value: unknown): JsonObject {
  const payload = object(value)
  const type = string(payload.type)
  const fields = payloadFields[type]
  if (!fields) throw new Error('unknown payload type')
  exactKeys(payload, fields)
  const optionalIds = new Set(['abandonedCycleId', 'parentCycleId'])
  for (const [key, field] of Object.entries(payload)) {
    if (key.endsWith('Id')) {
      if (field === null) {
        if (!optionalIds.has(key)) throw new Error('invalid UUIDv7')
      } else {
        uuid(field)
      }
    }
  }
  for (const key of ['text', 'reason']) {
    if (key in payload && payload[key] !== null) {
      const value = string(payload[key])
      if (value.length === 0) throw new Error(`invalid ${key}`)
      if (key === 'reason' && new TextEncoder().encode(value).length > 4096) {
        throw new Error('invalid reason')
      }
    }
  }
  if ('role' in payload && !['user', 'assistant'].includes(string(payload.role))) throw new Error('invalid role')
  if ('outcome' in payload) {
    const allowed = type === 'taskRun.completed'
      ? ['success', 'failure']
      : ['succeeded', 'failed_before_commit', 'failed_after_commit', 'uncertain', 'cancelled']
    if (!allowed.includes(string(payload.outcome))) throw new Error('invalid outcome')
  }
  if (
    'disposition' in payload
    && !['continue', 'wait', 'complete', 'fail'].includes(string(payload.disposition))
  ) throw new Error('invalid disposition')
  if (
    'source' in payload
    && !['external_input', 'approval', 'child_task_run', 'timer', 'reconciliation'].includes(string(payload.source))
  ) throw new Error('invalid source')
  if (type === 'taskRun.completed') {
    if (payload.outcome === 'success' && payload.reason !== null) throw new Error('invalid reason')
    if (payload.outcome === 'failure' && payload.reason === null) throw new Error('invalid reason')
  }
  for (const key of [
    'newGeneration',
    'ordinal',
    'revision',
    'sequence',
  ]) {
    if (
      key in payload
      && (!Number.isSafeInteger(payload[key]) || (payload[key] as number) < 1)
    ) throw new Error(`invalid ${key}`)
  }
  for (const key of ['delayMillis', 'proposalIndex']) {
    if (
      key in payload
      && (!Number.isSafeInteger(payload[key]) || (payload[key] as number) < 0)
    ) throw new Error(`invalid ${key}`)
  }
  for (const key of ['activatedAtUnixMicros', 'dueAtUnixMicros']) {
    if (key in payload && !Number.isSafeInteger(payload[key])) throw new Error(`invalid ${key}`)
  }
  if ('expectedProposalIndexes' in payload) {
    if (
      !Array.isArray(payload.expectedProposalIndexes)
      || payload.expectedProposalIndexes.some(value => !Number.isSafeInteger(value) || value < 0)
    ) {
      throw new Error('invalid proposal indexes')
    }
  }
  return payload
}

function parseCanonicalEvent(value: unknown, delivered: boolean): JsonObject {
  const event = object(value)
  const expectedFields = [
    'aggregateId',
    'aggregateType',
    'causationEventId',
    'correlationId',
    'correlationType',
    'eventId',
    'eventType',
    'integrityDigest',
    'payload',
    'replayBindingId',
    'schemaVersion',
    'sensitivity',
    'sequence',
    'timestampUnixMicros',
  ]
  if (delivered) expectedFields.push('cursor')
  exactKeys(event, expectedFields)
  uuid(event.aggregateId)
  uuid(event.eventId)
  uuid(event.correlationId)
  if (event.causationEventId !== null) uuid(event.causationEventId)
  if (delivered) cursor(event.cursor)
  if (!Number.isSafeInteger(event.sequence) || (event.sequence as number) < 1) throw new Error('invalid sequence')
  if (!Number.isSafeInteger(event.timestampUnixMicros)) throw new Error('invalid timestamp')
  if (event.schemaVersion !== 1) throw new Error('invalid schema version')
  if (!['conversation', 'taskRun'].includes(string(event.aggregateType))) throw new Error('invalid aggregate type')
  if (!['conversation', 'taskRun'].includes(string(event.correlationType))) throw new Error('invalid correlation type')
  if (!['public', 'internal', 'sensitive'].includes(string(event.sensitivity))) throw new Error('invalid sensitivity')
  if (!LOWER_HEX_32.test(string(event.integrityDigest))) throw new Error('invalid integrity digest')
  if (!LOWER_HEX_16.test(string(event.replayBindingId))) throw new Error('invalid replay binding')
  const eventType = string(event.eventType)
  const payload = parsePayload(event.payload)
  if (eventType !== payload.type) throw new Error('event type mismatch')
  return event
}

function parseReplayEvent(value: unknown): JsonObject {
  return parseCanonicalEvent(value, true)
}

function parseSseDelivery(value: unknown): JsonObject {
  const delivery = object(value)
  exactKeys(delivery, [
    'canonicalEvent',
    'deliverySequence',
    'liveDeliveryId',
    'replayCursor',
    'replaySessionId',
    'transportVersion',
  ])
  if (delivery.transportVersion !== 1) throw new Error('invalid transport version')
  if (!Number.isSafeInteger(delivery.deliverySequence) || (delivery.deliverySequence as number) < 1) {
    throw new Error('invalid delivery sequence')
  }
  uuid(delivery.replaySessionId)
  if (delivery.liveDeliveryId !== null) uuid(delivery.liveDeliveryId)
  cursor(delivery.replayCursor)
  parseCanonicalEvent(delivery.canonicalEvent, false)
  return delivery
}

function golden(name: string): unknown {
  return JSON.parse(readFileSync(resolve(process.cwd(), 'contracts/gocode-ui-client-1/golden', name), 'utf8'))
}

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
