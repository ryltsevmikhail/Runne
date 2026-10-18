import { invoke as tauriInvoke } from '@tauri-apps/api/core'

export type PermissionMode = 'ask_always' | 'risk_based' | 'full_access'
export type PermissionContainment = 'workspace_bound_v1' | 'same_user_composite_v1'
export type PermissionNetworkState = 'unavailable' | 'brokered' | 'broad_same_user'
export type PermissionNotReadyReason = 'native_containment' | 'composite_policy_unenforceable' | 'preset_unavailable'
export type PermissionEffectiveState =
  | { readonly state: 'notReady', readonly reason: 'native_containment' | 'composite_policy_unenforceable' | 'preset_unavailable' }
  | { readonly state: 'ready', readonly mode: PermissionMode, readonly containment: PermissionContainment }

export interface PermissionModeStatus {
  readonly selectedMode: PermissionMode
  readonly effective: PermissionEffectiveState
  readonly authorizationRevision: number
  readonly presetVersion: 1
  readonly managedPolicyVersion: number
  readonly pendingApprovals: number
  readonly containment: PermissionContainment | null
  readonly networkState: PermissionNetworkState
  readonly expiresAtUnixMs: number | null
}

export interface PermissionModeIntent {
  readonly workspaceId: string
  readonly commandId: string
  readonly requestedMode: PermissionMode
  readonly expectedAuthorizationRevision: number
  readonly idempotencyKey: string
  readonly request: {
    readonly workspaceId: readonly number[]
    readonly commandId: readonly number[]
    readonly idempotencyKey: string
    readonly expectedAuthorizationRevision: number
    readonly requestedMode: PermissionMode
    readonly presetVersion: 1
    readonly expiresAtUnixMs: null
  }
}

export interface PermissionModeRecoveryAddress {
  readonly version: 1
  readonly workspaceId: string
  readonly commandId: string
  readonly requestedMode: PermissionMode
  readonly expectedAuthorizationRevision: number
  readonly idempotencyKey: string
}

export type PermissionModeCommandStatus =
  | { readonly state: 'pending_native_confirmation' | 'pending_reauthentication', readonly commandId: string, readonly expiresAtUnixMs: number }
  | { readonly state: 'committed' | 'cancelled' | 'expired' | 'invalidated', readonly commandId: string }

type Invoke = (command: string, args?: Record<string, unknown>) => Promise<unknown>
const uuidV7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const modes: readonly PermissionMode[] = ['ask_always', 'risk_based', 'full_access']
const containments: readonly PermissionContainment[] = ['workspace_bound_v1', 'same_user_composite_v1']
const networks: readonly PermissionNetworkState[] = ['unavailable', 'brokered', 'broad_same_user']

export async function getPermissionModeStatus(
  workspaceId: string,
  invoke: Invoke = tauriInvoke,
): Promise<PermissionModeStatus> {
  requireId(workspaceId)
  const value = await invoke('get_permission_mode_status', { workspaceId })
  const status = parseStatus(value)
  return status
}

export function createPermissionModeIntent(
  workspaceId: string,
  requestedMode: PermissionMode,
  expectedAuthorizationRevision: number,
  now = Date.now(),
): PermissionModeIntent {
  requireId(workspaceId)
  if (!modes.includes(requestedMode) || !safeRevision(expectedAuthorizationRevision)
    || !Number.isSafeInteger(now) || now <= 0 || !globalThis.crypto?.getRandomValues) {
    throw new Error('Invalid permission mode intent')
  }
  const commandBytes = uuidV7Bytes(now)
  const commandId = formatId(commandBytes)
  return {
    workspaceId,
    commandId,
    requestedMode,
    expectedAuthorizationRevision,
    idempotencyKey: commandId,
    request: {
      workspaceId: idBytes(workspaceId),
      commandId: Array.from(commandBytes),
      idempotencyKey: commandId,
      expectedAuthorizationRevision,
      requestedMode,
      presetVersion: 1,
      expiresAtUnixMs: null,
    },
  }
}

export function permissionModeRecoveryAddress(intent: PermissionModeIntent): PermissionModeRecoveryAddress {
  return {
    version: 1,
    workspaceId: intent.workspaceId,
    commandId: intent.commandId,
    requestedMode: intent.requestedMode,
    expectedAuthorizationRevision: intent.expectedAuthorizationRevision,
    idempotencyKey: intent.idempotencyKey,
  }
}

export function restorePermissionModeIntent(value: unknown, workspaceId: string): PermissionModeIntent | null {
  if (!exact(value, ['version', 'workspaceId', 'commandId', 'requestedMode', 'expectedAuthorizationRevision', 'idempotencyKey'])
    || value.version !== 1 || value.workspaceId !== workspaceId
    || !modes.includes(value.requestedMode as PermissionMode)
    || !safeRevision(value.expectedAuthorizationRevision)
    || value.idempotencyKey !== value.commandId) return null
  try {
    requireId(workspaceId)
    requireId(value.commandId as string)
  }
  catch {
    return null
  }
  const commandId = value.commandId as string
  const requestedMode = value.requestedMode as PermissionMode
  const expectedAuthorizationRevision = value.expectedAuthorizationRevision as number
  return {
    workspaceId,
    commandId,
    requestedMode,
    expectedAuthorizationRevision,
    idempotencyKey: commandId,
    request: {
      workspaceId: idBytes(workspaceId),
      commandId: idBytes(commandId),
      idempotencyKey: commandId,
      expectedAuthorizationRevision,
      requestedMode,
      presetVersion: 1,
      expiresAtUnixMs: null,
    },
  }
}

export async function requestPermissionModeChange(
  intent: PermissionModeIntent,
  invoke: Invoke = tauriInvoke,
): Promise<PermissionModeCommandStatus> {
  const value = await invoke('request_permission_mode_change', { request: intent.request })
  return parseCommandStatus(value, intent)
}

export async function getPermissionModeCommandStatus(
  intent: PermissionModeIntent,
  invoke: Invoke = tauriInvoke,
): Promise<PermissionModeCommandStatus> {
  const value = await invoke('get_permission_mode_command_status', {
    workspaceId: intent.workspaceId,
    commandId: intent.commandId,
  })
  return parseCommandStatus(value, intent)
}

function parseStatus(value: unknown): PermissionModeStatus {
  if (!exact(value, ['selectedMode', 'effective', 'authorizationRevision', 'presetVersion', 'managedPolicyVersion', 'pendingApprovalIds', 'containment', 'networkState', 'expiresAtUnixMs'])
    || !modes.includes(value.selectedMode as PermissionMode) || value.presetVersion !== 1
    || !safeRevision(value.authorizationRevision) || !safeRevision(value.managedPolicyVersion)
    || !Array.isArray(value.pendingApprovalIds) || value.pendingApprovalIds.length > 4096
    || !value.pendingApprovalIds.every(id => idBytesFromJson(id) !== null)
    || !(value.containment === null || containments.includes(value.containment as PermissionContainment))
    || !networks.includes(value.networkState as PermissionNetworkState)
    || !(value.expiresAtUnixMs === null || positiveSafe(value.expiresAtUnixMs))) {
    throw new Error('Invalid permission mode status')
  }
  const effective = parseEffective(value.effective)
  if (effective.state === 'ready'
    && (effective.mode !== value.selectedMode || value.containment !== effective.containment)) {
    throw new Error('Incoherent permission mode status')
  }
  return {
    selectedMode: value.selectedMode as PermissionMode,
    effective,
    authorizationRevision: value.authorizationRevision as number,
    presetVersion: 1,
    managedPolicyVersion: value.managedPolicyVersion as number,
    pendingApprovals: value.pendingApprovalIds.length,
    containment: value.containment as PermissionContainment | null,
    networkState: value.networkState as PermissionNetworkState,
    expiresAtUnixMs: value.expiresAtUnixMs as number | null,
  }
}

function parseEffective(value: unknown): PermissionEffectiveState {
  if (!record(value)) throw new Error('Invalid effective permission mode')
  if (value.state === 'notReady' && exact(value, ['state', 'reason'])
    && ['native_containment', 'composite_policy_unenforceable', 'preset_unavailable'].includes(String(value.reason))) {
    return { state: 'notReady', reason: value.reason as PermissionNotReadyReason }
  }
  if (value.state === 'ready' && exact(value, ['state', 'mode', 'preset_version', 'scope_digest', 'containment'])
    && modes.includes(value.mode as PermissionMode) && value.preset_version === 1
    && Array.isArray(value.scope_digest) && value.scope_digest.length === 32
    && value.scope_digest.every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255)
    && value.scope_digest.some(byte => byte !== 0)
    && containments.includes(value.containment as PermissionContainment)) {
    return { state: 'ready', mode: value.mode as PermissionMode, containment: value.containment as PermissionContainment }
  }
  throw new Error('Invalid effective permission mode')
}

function parseCommandStatus(value: unknown, intent: PermissionModeIntent): PermissionModeCommandStatus {
  if (!record(value) || typeof value.state !== 'string') throw new Error('Invalid permission mode command status')
  if (value.state === 'pending_native_confirmation' || value.state === 'pending_reauthentication') {
    if (!exact(value, ['state', 'commandId', 'expiresAtUnixMs'])
      || idFromJson(value.commandId) !== intent.commandId || !positiveSafe(value.expiresAtUnixMs)) {
      throw new Error('Mismatched permission mode command status')
    }
    return { state: value.state, commandId: intent.commandId, expiresAtUnixMs: value.expiresAtUnixMs as number }
  }
  if (value.state === 'committed' && exact(value, ['state', 'receipt']) && record(value.receipt)) {
    const receipt = value.receipt
    if (!exact(receipt, ['commandId', 'idempotencyKey', 'intentDigest', 'authorizationRevision', 'selectedMode', 'history'])
      || idFromJson(receipt.commandId) !== intent.commandId || receipt.idempotencyKey !== intent.idempotencyKey
      || receipt.selectedMode !== intent.requestedMode || !positiveSafe(receipt.authorizationRevision)
      || receipt.authorizationRevision !== intent.expectedAuthorizationRevision + 1
      || !Array.isArray(receipt.intentDigest) || receipt.intentDigest.length !== 32
      || !record(receipt.history) || receipt.history.selectedMode !== intent.requestedMode
      || receipt.history.authorizationRevision !== receipt.authorizationRevision
      || receipt.history.presetVersion !== 1 || receipt.history.expiresAtUnixMs !== null) {
      throw new Error('Mismatched permission mode receipt')
    }
    return { state: 'committed', commandId: intent.commandId }
  }
  if (['cancelled', 'expired', 'invalidated'].includes(value.state)
    && exact(value, ['state', 'commandId']) && idFromJson(value.commandId) === intent.commandId) {
    return { state: value.state as 'cancelled' | 'expired' | 'invalidated', commandId: intent.commandId }
  }
  throw new Error('Invalid permission mode command status')
}

function uuidV7Bytes(now: number): Uint8Array {
  const bytes = new Uint8Array(16)
  const random = globalThis.crypto.getRandomValues(new Uint8Array(10))
  bytes[0] = Math.floor(now / 2 ** 40) & 255
  bytes[1] = Math.floor(now / 2 ** 32) & 255
  bytes[2] = Math.floor(now / 2 ** 24) & 255
  bytes[3] = Math.floor(now / 2 ** 16) & 255
  bytes[4] = Math.floor(now / 2 ** 8) & 255
  bytes[5] = now & 255
  bytes[6] = 0x70 | (random[0]! & 0x0f)
  bytes[7] = random[1]!
  bytes[8] = 0x80 | (random[2]! & 0x3f)
  bytes.set(random.subarray(3), 9)
  return bytes
}

function idBytes(value: string): number[] {
  requireId(value)
  return Array.from({ length: 16 }, (_, index) => Number.parseInt(value.replaceAll('-', '').slice(index * 2, index * 2 + 2), 16))
}

function idBytesFromJson(value: unknown): number[] | null {
  return Array.isArray(value) && value.length === 16
    && value.every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255) ? value as number[] : null
}

function idFromJson(value: unknown): string | null {
  const bytes = idBytesFromJson(value)
  if (bytes === null) return null
  const hex = bytes.map(byte => byte.toString(16).padStart(2, '0')).join('')
  const id = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
  return uuidV7.test(id) ? id : null
}

function formatId(bytes: Uint8Array): string {
  return idFromJson(Array.from(bytes)) ?? (() => { throw new Error('Invalid generated permission command ID') })()
}

function requireId(value: string): void {
  if (!uuidV7.test(value)) throw new Error('Invalid workspace identity')
}

function safeRevision(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
}

function positiveSafe(value: unknown): value is number {
  return safeRevision(value) && value > 0
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function exact(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  return record(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key))
}
