import { invoke as tauriInvoke } from '@tauri-apps/api/core'

export type WorkspaceChangeKind = 'added' | 'modified' | 'deleted'
export type WorkspaceDiffLineKind = 'context' | 'added' | 'removed'

export interface WorkspaceChangeEntry {
  readonly path: string
  readonly kind: WorkspaceChangeKind
  readonly additions: number
  readonly deletions: number
}

export interface WorkspaceChangeSet {
  readonly items: readonly WorkspaceChangeEntry[]
}

export interface WorkspaceDiffLine {
  readonly kind: WorkspaceDiffLineKind
  readonly text: string
}

export interface WorkspaceDiffHunk {
  readonly oldStart: number
  readonly oldLines: number
  readonly newStart: number
  readonly newLines: number
  readonly lines: readonly WorkspaceDiffLine[]
}

export interface WorkspaceDiff {
  readonly path: string
  readonly kind: WorkspaceChangeKind
  readonly hunks: readonly WorkspaceDiffHunk[]
  readonly truncated: boolean
}

type Invoke = (command: string, args?: Record<string, unknown>) => Promise<unknown>

const MAX_PATH_BYTES = 4096
const MAX_PAGE_SIZE = 200
const MAX_HUNKS = 512
const MAX_LINES = 65_536
const MAX_LINES_PER_HUNK = 16_384
const MAX_LINE_BYTES = 16 * 1024
const MAX_DIFF_BYTES = 1_048_576

export async function listWorkspaceChanges(
  workspaceId: string,
  limit = 50,
  invoke: Invoke = tauriInvoke,
): Promise<WorkspaceChangeSet> {
  validateId(workspaceId)
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_PAGE_SIZE) {
    throw new Error('Invalid workspace change limit')
  }
  const value = await invoke('list_workspace_changes', { workspaceId, limit })
  if (!isChangeSet(value, limit)) throw new Error('Invalid workspace change set')
  return value
}

export async function readWorkspaceDiff(
  workspaceId: string,
  path: string,
  invoke: Invoke = tauriInvoke,
): Promise<WorkspaceDiff> {
  validateId(workspaceId)
  validatePath(path)
  const value = await invoke('read_workspace_diff', { workspaceId, path })
  if (!isDiff(value, path)) throw new Error('Invalid workspace diff')
  return value
}

function isChangeSet(value: unknown, limit: number): value is WorkspaceChangeSet {
  if (!isRecord(value) || Object.keys(value).length !== 1 || !Array.isArray(value.items) || value.items.length > limit) return false
  return value.items.every(isChangeEntry)
    && value.items.every((entry, index, items) => index === 0 || (items[index - 1]?.path ?? '') < entry.path)
}

function isChangeEntry(value: unknown): value is WorkspaceChangeEntry {
  return isRecord(value)
    && Object.keys(value).length === 4
    && typeof value.path === 'string'
    && isCanonicalPath(value.path)
    && (value.kind === 'added' || value.kind === 'modified' || value.kind === 'deleted')
    && boundedInteger(value.additions)
    && boundedInteger(value.deletions)
}

function isDiff(value: unknown, path: string): value is WorkspaceDiff {
  if (!isRecord(value) || Object.keys(value).length !== 4 || value.path !== path) return false
  if (!isCanonicalPath(value.path) || !['added', 'modified', 'deleted'].includes(String(value.kind))) return false
  if (typeof value.truncated !== 'boolean' || !Array.isArray(value.hunks) || value.hunks.length > MAX_HUNKS) return false
  let lines = 0
  let bytes = 0
  for (const [index, hunk] of value.hunks.entries()) {
    if (!isHunk(hunk) || (index > 0 && !orderedHunks(value.hunks[index - 1], hunk))) return false
    lines += hunk.lines.length
    bytes += hunk.lines.reduce((total, line) => total + new TextEncoder().encode(line.text).length, 0)
    if (lines > MAX_LINES || bytes > MAX_DIFF_BYTES) return false
  }
  return true
}

function isHunk(value: unknown): value is WorkspaceDiffHunk {
  if (!isRecord(value) || Object.keys(value).length !== 5 || !Array.isArray(value.lines) || value.lines.length > MAX_LINES_PER_HUNK) return false
  return boundedInteger(value.oldStart, 1)
    && boundedInteger(value.oldLines)
    && boundedInteger(value.newStart, 1)
    && boundedInteger(value.newLines)
    && value.lines.every(isLine)
    && value.lines.filter(line => line.kind !== 'added').length === value.oldLines
    && value.lines.filter(line => line.kind !== 'removed').length === value.newLines
}

function orderedHunks(previous: unknown, current: WorkspaceDiffHunk): boolean {
  return isRecord(previous)
    && typeof previous.oldStart === 'number'
    && typeof previous.newStart === 'number'
    && (previous.oldStart < current.oldStart
      || (previous.oldStart === current.oldStart && previous.newStart < current.newStart))
}

function isLine(value: unknown): value is WorkspaceDiffLine {
  return isRecord(value)
    && Object.keys(value).length === 2
    && (value.kind === 'context' || value.kind === 'added' || value.kind === 'removed')
    && typeof value.text === 'string'
    && new TextEncoder().encode(value.text).length <= MAX_LINE_BYTES
    && !hasInvalidLineCharacter(value.text)
}

function validateId(value: string): void {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(value)) throw new Error('Invalid workspace identifier')
}

function validatePath(value: string): void {
  if (!isCanonicalPath(value)) throw new Error('Invalid workspace diff path')
}

function isCanonicalPath(value: string): boolean {
  return new TextEncoder().encode(value).length <= MAX_PATH_BYTES
    && value.length > 0
    && !value.startsWith('/')
    && !value.includes('\\')
    && !hasInvalidPathCharacter(value)
    && !value.split('/').some(part => part.length === 0 || part === '.' || part === '..')
}

function boundedInteger(value: unknown, minimum = 0): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= minimum && value <= 0xffffffff
}

function hasInvalidLineCharacter(value: string): boolean {
  return Array.from(value).some(character => {
    const code = character.charCodeAt(0)
    return (code < 0x20 && code !== 0x09) || code === 0x7f
  })
}

function hasInvalidPathCharacter(value: string): boolean {
  return Array.from(value).some(character => {
    const code = character.charCodeAt(0)
    return code < 0x20 || code === 0x7f
  })
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}
