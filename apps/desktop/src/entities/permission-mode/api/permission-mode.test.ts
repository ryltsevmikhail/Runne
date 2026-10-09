import { describe, expect, it, vi } from 'vitest'

import {
  createPermissionModeIntent,
  getPermissionModeCommandStatus,
  getPermissionModeStatus,
  permissionModeRecoveryAddress,
  requestPermissionModeChange,
  restorePermissionModeIntent,
} from './permission-mode'

const workspaceId = '01890e00-0000-7000-8000-000000000002'
const commandId = '01890e00-0000-7000-8000-000000000003'
const idBytes = (id: string) => id.replaceAll('-', '').match(/.{2}/g)!.map(byte => Number.parseInt(byte, 16))

const status = {
  selectedMode: 'full_access',
  effective: { state: 'notReady', reason: 'native_containment' },
  authorizationRevision: 12,
  presetVersion: 1,
  managedPolicyVersion: 4,
  pendingApprovalIds: [idBytes(commandId)],
  containment: null,
  networkState: 'unavailable',
  expiresAtUnixMs: 1_900_000_000_000,
}

describe('permission mode adapter', () => {
  it('preserves selected and effective state independently with revision and scope facts', async () => {
    const invoke = vi.fn().mockResolvedValue(status)
    await expect(getPermissionModeStatus(workspaceId, invoke)).resolves.toEqual({
      selectedMode: 'full_access',
      effective: { state: 'notReady', reason: 'native_containment' },
      authorizationRevision: 12,
      presetVersion: 1,
      managedPolicyVersion: 4,
      pendingApprovals: 1,
      containment: null,
      networkState: 'unavailable',
      expiresAtUnixMs: 1_900_000_000_000,
    })
    expect(invoke).toHaveBeenCalledWith('get_permission_mode_status', { workspaceId })
  })

  it('creates one UUIDv7 public intent and submits it once', async () => {
    const intent = createPermissionModeIntent(workspaceId, 'risk_based', 12, 1_700_000_000_000)
    const invoke = vi.fn().mockResolvedValue({
      state: 'pending_native_confirmation',
      commandId: idBytes(intent.commandId),
      expiresAtUnixMs: 1_700_000_060_000,
    })
    await expect(requestPermissionModeChange(intent, invoke)).resolves.toMatchObject({
      state: 'pending_native_confirmation',
      commandId: intent.commandId,
    })
    expect(intent.commandId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
    expect(intent.request).toMatchObject({
      workspaceId: idBytes(workspaceId),
      commandId: idBytes(intent.commandId),
      idempotencyKey: intent.commandId,
      expectedAuthorizationRevision: 12,
      requestedMode: 'risk_based',
      presetVersion: 1,
      expiresAtUnixMs: null,
    })
    expect(invoke).toHaveBeenCalledTimes(1)
  })

  it('reads back only the original command and rejects a mismatched receipt', async () => {
    const intent = createPermissionModeIntent(workspaceId, 'ask_always', 12, 1_700_000_000_000)
    const pending = {
      state: 'pending_reauthentication',
      commandId: idBytes(intent.commandId),
      expiresAtUnixMs: 1_700_000_060_000,
    }
    const invoke = vi.fn().mockResolvedValue(pending)
    await expect(getPermissionModeCommandStatus(intent, invoke)).resolves.toEqual({
      state: 'pending_reauthentication',
      commandId: intent.commandId,
      expiresAtUnixMs: 1_700_000_060_000,
    })
    expect(invoke).toHaveBeenCalledWith('get_permission_mode_command_status', {
      workspaceId,
      commandId: intent.commandId,
    })
    await expect(getPermissionModeCommandStatus(intent, vi.fn().mockResolvedValue({
      ...pending,
      commandId: idBytes(commandId),
    }))).rejects.toThrow('Mismatched permission mode command status')
  })

  it('restores only the exact workspace-scoped command address', () => {
    const intent = createPermissionModeIntent(workspaceId, 'risk_based', 12, 1_700_000_000_000)
    const address = permissionModeRecoveryAddress(intent)
    expect(restorePermissionModeIntent(address, workspaceId)).toEqual(intent)
    expect(restorePermissionModeIntent(address, '01890e00-0000-7000-8000-000000000004')).toBeNull()
    expect(restorePermissionModeIntent({ ...address, idempotencyKey: 'another-key' }, workspaceId)).toBeNull()
  })

  it('rejects unknown projection shapes instead of implying effective access', async () => {
    await expect(getPermissionModeStatus(workspaceId, vi.fn().mockResolvedValue({
      ...status,
      effective: { state: 'ready', mode: 'full_access', preset_version: 1, scope_digest: [0], containment: 'same_user_composite_v1' },
    }))).rejects.toThrow('Invalid effective permission mode')
  })
})
