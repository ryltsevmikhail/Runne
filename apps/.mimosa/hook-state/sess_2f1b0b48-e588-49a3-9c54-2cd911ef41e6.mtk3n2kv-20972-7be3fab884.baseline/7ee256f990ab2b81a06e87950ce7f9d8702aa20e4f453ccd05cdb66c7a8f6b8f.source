import { invoke as tauriInvoke } from '@tauri-apps/api/core'

export type ProcessState = 'starting' | 'running' | 'stopping' | 'exited' | 'failed'
export type ProcessOutputStream = 'stdout' | 'stderr'

export interface ProcessSnapshot {
  readonly processId: string
  readonly invocationId: string
  readonly workspaceId: string
  readonly state: ProcessState
  readonly version: number
  readonly nextOutputSequence: number
}

export interface ProcessOutputChunk {
  readonly sequence: number
  readonly stream: ProcessOutputStream
  readonly text: string
}

export interface ProcessOutputPage {
  readonly chunks: readonly ProcessOutputChunk[]
}

type Invoke = (command: string, args?: Record<string, unknown>) => Promise<unknown>

const MAX_OUTPUT_CHUNKS = 128
const MAX_OUTPUT_BYTES = 7 * 1024 * 1024

export async function startProcess(
  workspaceId: string,
  taskRunId: string,
  attemptId: string,
  invocationId: string,
  invoke: Invoke = tauriInvoke,
): Promise<ProcessSnapshot> {
  for (const id of [workspaceId, taskRunId, attemptId, invocationId]) validateId(id)
  return snapshot(await invoke('start_process', { workspaceId, taskRunId, attemptId, invocationId }))
}

export async function getProcess(
  processId: string,
  invoke: Invoke = tauriInvoke,
): Promise<ProcessSnapshot> {
  validateId(processId)
  return snapshot(await invoke('get_process', { processId }))
}

export async function readProcessOutput(
  processId: string,
  afterSequence = 0,
  limit = 64,
  invoke: Invoke = tauriInvoke,
): Promise<ProcessOutputPage> {
  validateId(processId)
  if (!Number.isSafeInteger(afterSequence) || afterSequence < 0) throw new Error('Invalid output cursor')
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_OUTPUT_CHUNKS) throw new Error('Invalid output limit')
  const value = await invoke('read_process_output', { processId, afterSequence, limit })
  if (!isPage(value, limit)) throw new Error('Invalid process output')
  return value
}

export async function stopProcess(
  processId: string,
  expectedVersion: number,
  invoke: Invoke = tauriInvoke,
): Promise<ProcessSnapshot> {
  validateId(processId)
  if (!Number.isSafeInteger(expectedVersion) || expectedVersion < 1) throw new Error('Invalid process version')
  return snapshot(await invoke('stop_process', { processId, expectedVersion }))
}

function snapshot(value: unknown): ProcessSnapshot {
  if (!isRecord(value) || Object.keys(value).length !== 6
    || !isId(value.processId) || !isId(value.invocationId) || !isId(value.workspaceId)
    || !['starting', 'running', 'stopping', 'exited', 'failed'].includes(String(value.state))
    || !positiveInteger(value.version) || !positiveInteger(value.nextOutputSequence)) {
    throw new Error('Invalid process snapshot')
  }
  return value as unknown as ProcessSnapshot
}

function isPage(value: unknown, limit: number): value is ProcessOutputPage {
  if (!isRecord(value) || Object.keys(value).length !== 1 || !Array.isArray(value.chunks)
    || value.chunks.length > limit || value.chunks.length > MAX_OUTPUT_CHUNKS) return false
  let bytes = 0
  let previous = 0
  for (const chunk of value.chunks) {
    if (!isRecord(chunk) || Object.keys(chunk).length !== 3 || !positiveInteger(chunk.sequence)
      || (chunk.stream !== 'stdout' && chunk.stream !== 'stderr') || typeof chunk.text !== 'string'
      || hasControl(chunk.text)) return false
    if (chunk.sequence <= previous) return false
    previous = chunk.sequence
    bytes += new TextEncoder().encode(chunk.text).length
    if (bytes > MAX_OUTPUT_BYTES) return false
  }
  return true
}

function hasControl(value: string): boolean {
  return Array.from(value).some(character => {
    const code = character.codePointAt(0) ?? 0
    return (code < 0x20 && code !== 0x09 && code !== 0x0a)
      || code === 0x7f || code === 0x009b || code === 0x009d
      || code === 0x061c || code === 0x200e || code === 0x200f
      || (code >= 0x202a && code <= 0x202e) || (code >= 0x2066 && code <= 0x2069)
  })
}

function validateId(value: string): void {
  if (!isId(value)) throw new Error('Invalid process identifier')
}

function isId(value: unknown): value is string {
  return typeof value === 'string'
    && /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(value)
}

function positiveInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}
