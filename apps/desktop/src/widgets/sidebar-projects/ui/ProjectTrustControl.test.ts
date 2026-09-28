import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const api = vi.hoisted(() => ({
  get: vi.fn(), request: vi.fn(), mark: vi.fn(), revision: vi.fn(() => 0),
}))
vi.mock('@/entities/project', () => ({
  getProjectTrustControl: api.get,
  requestProjectTrustControl: api.request,
  markProjectTrustChanged: api.mark,
  projectTrustRevision: api.revision,
}))
vi.mock('@/shared/i18n', () => ({ translate: (key: string) => key }))

import ProjectTrustControl from './ProjectTrustControl.vue'

const projectA = '01890e00-0000-7000-8000-000000000001'
const projectB = '01890e00-0000-7000-8000-000000000009'
const workspaceA = '01890e00-0000-7000-8000-000000000002'
const workspaceB = '01890e00-0000-7000-8000-000000000008'
function state(projectId = projectA, workspaceId = workspaceA, patch: Record<string, unknown> = {}) {
  return {
    projectId, projectName: 'safe project', projectVersion: '1', workspaceId,
    workspaceName: 'safe workspace', workspaceVersion: '2', status: 'untrusted',
    managedDenyMask: 0, provenance: 'default', epoch: '1', revision: '0',
    rootAdmissionVersion: '1', ...patch,
  }
}
function mountControl(props = { projectId: projectA, workspaceId: workspaceA, disabled: false }) {
  return mount(ProjectTrustControl, { props })
}

describe('ProjectTrustControl', () => {
  beforeEach(() => { api.get.mockReset(); api.request.mockReset(); api.mark.mockReset() })

  it('reads safe state but never grants on mount; missing root blocks confirmation', async () => {
    api.get.mockResolvedValue(state(projectA, workspaceA, { rootAdmissionVersion: null }))
    const wrapper = mountControl()
    await flushPromises()
    expect(api.get).toHaveBeenCalledWith(projectA, workspaceA)
    expect(api.request).not.toHaveBeenCalled()
    expect(wrapper.find('button.trust-action').attributes('disabled')).toBeDefined()
  })

  it('sends only the explicit action and leaves a native-dialog cancellation unchanged', async () => {
    api.get.mockResolvedValue(state())
    api.request.mockResolvedValue({ outcome: 'cancelled', snapshot: null })
    const wrapper = mountControl()
    await flushPromises()
    await wrapper.get('button.trust-action').trigger('click')
    await flushPromises()
    expect(api.request).toHaveBeenCalledOnce()
    expect(api.request).toHaveBeenCalledWith(projectA, workspaceA, 'confirm_project')
    expect(wrapper.get('.trust-status').attributes('data-status')).toBe('untrusted')
  })

  it('refreshes after an unknown result without resending the decision', async () => {
    api.get.mockResolvedValue(state())
    api.request.mockRejectedValue(new Error('unknown'))
    const wrapper = mountControl()
    await flushPromises()
    await wrapper.get('button.trust-action').trigger('click')
    await flushPromises()
    expect(api.request).toHaveBeenCalledOnce()
    expect(api.get).toHaveBeenCalledTimes(2)
    expect(wrapper.text()).toContain('projectTrust.changed')
  })

  it('does not offer an override for any managed policy mask', async () => {
    api.get.mockResolvedValue(state(projectA, workspaceA, { managedDenyMask: 4, provenance: 'managed' }))
    const wrapper = mountControl()
    await flushPromises()
    expect(wrapper.get('.trust-status').text()).toBe('projectTrust.managed')
    expect(wrapper.find('button.trust-action').exists()).toBe(false)
    expect(api.request).not.toHaveBeenCalled()
  })

  it('keeps revoke available for trusted state with a disconnected root', async () => {
    api.get.mockResolvedValue(state(projectA, workspaceA, { status: 'trusted', provenance: 'user', revision: '1', rootAdmissionVersion: null }))
    const wrapper = mountControl()
    await flushPromises()
    expect(wrapper.get('button.trust-action').text()).toBe('projectTrust.revoke')
    expect(wrapper.get('button.trust-action').attributes('disabled')).toBeUndefined()
  })

  it('ignores an old safe-state response after switching project and workspace', async () => {
    let resolveOld!: (value: ReturnType<typeof state>) => void
    api.get.mockImplementationOnce(() => new Promise(resolve => { resolveOld = resolve }))
      .mockResolvedValueOnce(state(projectB, workspaceB, { status: 'trusted', provenance: 'user', revision: '1' }))
    const wrapper = mountControl()
    await wrapper.setProps({ projectId: projectB, workspaceId: workspaceB, disabled: false })
    await flushPromises()
    resolveOld(state(projectA, workspaceA, { status: 'trusted', provenance: 'user', revision: '1' }))
    await flushPromises()
    expect(wrapper.get('.trust-status').attributes('data-status')).toBe('trusted')
    await wrapper.get('button.trust-action').trigger('click')
    expect(api.request).toHaveBeenCalledWith(projectB, workspaceB, 'revoke_project')
  })

  it('does not let an in-flight decision retarget a new selection', async () => {
    let resolveAction!: (value: { outcome: 'updated'; snapshot: ReturnType<typeof state> }) => void
    api.get.mockResolvedValueOnce(state()).mockResolvedValueOnce(state(projectB, workspaceB))
    api.request.mockImplementationOnce(() => new Promise(resolve => { resolveAction = resolve }))
    const wrapper = mountControl()
    await flushPromises()
    await wrapper.get('button.trust-action').trigger('click')
    await wrapper.setProps({ projectId: projectB, workspaceId: workspaceB, disabled: false })
    await flushPromises()
    expect(wrapper.get('button.trust-action').attributes('disabled')).toBeDefined()
    resolveAction({ outcome: 'updated', snapshot: state(projectA, workspaceA, { status: 'trusted', provenance: 'user', revision: '1' }) })
    await flushPromises()
    expect(wrapper.get('.trust-status').attributes('data-status')).toBe('untrusted')
    expect(api.request).toHaveBeenCalledOnce()
  })

  it('invalidates the project cache when a decision commits after the widget unmounts', async () => {
    let resolveAction!: (value: { outcome: 'updated'; snapshot: ReturnType<typeof state> }) => void
    api.get.mockResolvedValue(state())
    api.request.mockImplementationOnce(() => new Promise(resolve => { resolveAction = resolve }))
    const wrapper = mountControl()
    await flushPromises()
    await wrapper.get('button.trust-action').trigger('click')
    wrapper.unmount()
    resolveAction({ outcome: 'updated', snapshot: state(projectA, workspaceA, { status: 'trusted', provenance: 'user', revision: '1' }) })
    await flushPromises()
    expect(api.request).toHaveBeenCalledOnce()
    expect(api.mark).toHaveBeenCalledOnce()
    expect(api.mark).toHaveBeenCalledWith(projectA)
  })
})
