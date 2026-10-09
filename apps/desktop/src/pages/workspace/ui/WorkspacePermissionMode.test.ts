import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { PermissionModeCommandStatus, PermissionModeIntent, PermissionModeStatus } from '@/entities/permission-mode'
import WorkspacePermissionMode from './WorkspacePermissionMode.vue'

const workspaceId = '01890e00-0000-7000-8000-000000000002'

const status: PermissionModeStatus = {
  selectedMode: 'full_access',
  effective: { state: 'notReady', reason: 'native_containment' },
  authorizationRevision: 12,
  presetVersion: 1,
  managedPolicyVersion: 4,
  pendingApprovals: 1,
  containment: null,
  networkState: 'unavailable',
  expiresAtUnixMs: 1_900_000_000_000,
}

const pending = (intent: PermissionModeIntent) => ({
  state: 'pending_native_confirmation' as const,
  commandId: intent.commandId,
  expiresAtUnixMs: 1_700_000_060_000,
})

const savedIntents = new Map<string, string>()
beforeEach(() => {
  savedIntents.clear()
  vi.stubGlobal('localStorage', {
    getItem: (key: string) => savedIntents.get(key) ?? null,
    setItem: (key: string, value: string) => { savedIntents.set(key, value) },
    removeItem: (key: string) => { savedIntents.delete(key) },
  })
})
afterEach(() => vi.unstubAllGlobals())

function mountControl(props: {
  mutationAllowed?: boolean
  loadStatus?: (workspaceId: string) => Promise<PermissionModeStatus>
  requestChange?: (intent: PermissionModeIntent) => Promise<PermissionModeCommandStatus>
  readCommand?: (intent: PermissionModeIntent) => Promise<PermissionModeCommandStatus>
} = {}) {
  return mount(WorkspacePermissionMode, {
    props: { workspaceId, runtimeReady: true, mutationAllowed: true, loadStatus: async () => status, ...props },
    global: { stubs: { RouterLink: { template: '<a href="/approvals"><slot /></a>' } } },
  })
}

describe('workspace permission mode control', () => {
  it('shows selected and effective modes separately with current scope facts', async () => {
    const wrapper = mountControl()
    await flushPromises()
    expect(wrapper.text()).toContain('Full access')
    expect(wrapper.text()).toContain('Native containment is not ready')
    expect(wrapper.text()).toContain('12')
    expect(wrapper.text()).toContain('unavailable')
    expect(wrapper.get('a[href="/approvals"]').text()).toBe('1')
    expect(wrapper.findAll('button[aria-pressed="true"]')).toHaveLength(1)
    expect(wrapper.findAll('button[aria-pressed="false"]')).toHaveLength(2)
    expect(wrapper.findAll('button').find(button => button.text() === 'Full access')!.attributes('disabled')).toBeUndefined()
  })

  it('sends one intent, reads back the same command and never updates optimistically', async () => {
    let resolvePost!: (value: PermissionModeCommandStatus) => void
    const requestChange = vi.fn<
      (intent: PermissionModeIntent) => Promise<PermissionModeCommandStatus>
    >(() => new Promise<PermissionModeCommandStatus>(resolve => {
      resolvePost = resolve
    }))
    const readCommand = vi.fn(async (intent: PermissionModeIntent) => pending(intent))
    const wrapper = mountControl({ requestChange, readCommand })
    await flushPromises()
    const modeButton = wrapper.findAll('button').find(button => button.text() === 'Ask for permission')!
    await modeButton.trigger('click')
    await modeButton.trigger('click')
    expect(requestChange).toHaveBeenCalledTimes(1)
    expect(modeButton.attributes('disabled')).toBeDefined()
    const sentIntent = requestChange.mock.calls[0]![0] as PermissionModeIntent
    resolvePost(pending(sentIntent))
    await flushPromises()
    expect(readCommand).toHaveBeenCalledTimes(1)
    expect(readCommand.mock.calls[0]![0].commandId).toBe(sentIntent.commandId)
    expect(wrapper.get('[aria-pressed="true"]').text()).toBe('Full access')
    expect(wrapper.text()).toContain('Waiting for trusted native confirmation')
  })

  it('allows a fresh native confirmation for a selected mode that is not effective', async () => {
    const requestChange = vi.fn(async (intent: PermissionModeIntent) => pending(intent))
    const readCommand = vi.fn(async (intent: PermissionModeIntent) => pending(intent))
    const wrapper = mountControl({ requestChange, readCommand })
    await flushPromises()
    await wrapper.findAll('button').find(button => button.text() === 'Full access')!.trigger('click')
    await flushPromises()
    expect(requestChange).toHaveBeenCalledTimes(1)
    expect(readCommand).toHaveBeenCalledTimes(1)
    expect(wrapper.get('[aria-pressed="true"]').text()).toBe('Full access')
    expect(wrapper.text()).toContain('Native containment is not ready')
  })

  it.each([
    { code: 'permission_command_unknown', message: 'The result is unknown' },
    { code: 'permission_command_unavailable', message: 'Could not check this command status' },
  ])('recovers a lost acknowledgement after reconnect with GET only and the same ID ($code)', async ({ code, message }) => {
    const requestChange = vi.fn().mockRejectedValue(new Error('acknowledgement lost'))
    const seen: string[] = []
    const readCommand = vi.fn(async (intent: PermissionModeIntent) => {
      seen.push(intent.commandId)
      if (seen.length === 1) throw Object.assign(new Error('readback failed'), { code })
      return pending(intent)
    })
    const wrapper = mountControl({ requestChange, readCommand })
    await flushPromises()
    await wrapper.findAll('button').find(button => button.text() === 'Ask for permission')!.trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain(message)
    await wrapper.setProps({ runtimeReady: false })
    await flushPromises()
    await wrapper.setProps({ runtimeReady: true })
    await flushPromises()
    await wrapper.findAll('button').find(button => button.text() === 'Check command status')!.trigger('click')
    await flushPromises()
    expect(requestChange).toHaveBeenCalledTimes(1)
    expect(readCommand).toHaveBeenCalledTimes(3)
    expect(new Set(seen)).toEqual(new Set([seen[0]]))
    expect(wrapper.text()).toContain('Waiting for trusted native confirmation')
    expect(wrapper.findAll('button[aria-pressed="false"]')).toHaveLength(2)
  })

  it('keeps a lost command address across workspace switches and remounts', async () => {
    const otherWorkspace = '01890e00-0000-7000-8000-000000000004'
    const requestChange = vi.fn().mockRejectedValue(new Error('acknowledgement lost'))
    const seen: string[] = []
    const readCommand = vi.fn(async (intent: PermissionModeIntent) => {
      seen.push(intent.commandId)
      if (seen.length === 1) throw new Error('readback unavailable')
      return pending(intent)
    })
    const wrapper = mountControl({ requestChange, readCommand })
    await flushPromises()
    await wrapper.findAll('button').find(button => button.text() === 'Ask for permission')!.trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('The result is unknown')
    const originalCommand = requestChange.mock.calls[0]![0].commandId
    await wrapper.setProps({ workspaceId: otherWorkspace })
    await flushPromises()
    await wrapper.setProps({ workspaceId })
    await flushPromises()
    wrapper.unmount()

    const reopened = mountControl({ requestChange, readCommand })
    await flushPromises()
    expect(requestChange).toHaveBeenCalledTimes(1)
    expect(seen).toEqual([originalCommand, originalCommand, originalCommand])
    expect(reopened.text()).toContain('Waiting for trusted native confirmation')
    reopened.unmount()
  })

  it('keeps live read-only status visible but blocks mode requests', async () => {
    const loadStatus = vi.fn(async () => status)
    const requestChange = vi.fn(async (_intent: PermissionModeIntent) => pending(_intent))
    const wrapper = mountControl({ mutationAllowed: false, loadStatus, requestChange })
    await flushPromises()
    expect(loadStatus).toHaveBeenCalledTimes(1)
    expect(wrapper.text()).toContain('read-only')
    expect(wrapper.get('button').attributes('disabled')).toBeDefined()
    expect(requestChange).not.toHaveBeenCalled()
  })
})
