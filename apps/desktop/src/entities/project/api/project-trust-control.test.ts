import { describe, expect, it, vi } from 'vitest'
import { getProjectTrustControl, requestProjectTrustControl } from './projectTrustControl'

const projectId = '01890e00-0000-7000-8000-000000000001'
const workspaceId = '01890e00-0000-7000-8000-000000000002'
const snapshot = {
  projectId, projectName: 'project', projectVersion: '1', workspaceId,
  workspaceName: 'workspace', workspaceVersion: '2', status: 'untrusted',
  managedDenyMask: 0, provenance: 'default', epoch: '1', revision: '0', rootAdmissionVersion: '1',
}

describe('project trust control API', () => {
  it('accepts lossless canonical decimal versions and rejects overflow or aliases', async () => {
    const invoke = vi.fn().mockResolvedValue(snapshot)
    await expect(getProjectTrustControl(projectId, workspaceId, invoke)).resolves.toEqual(snapshot)
    invoke.mockResolvedValue({ ...snapshot, revision: '01' })
    await expect(getProjectTrustControl(projectId, workspaceId, invoke)).rejects.toThrow()
    invoke.mockResolvedValue({ ...snapshot, epoch: '18446744073709551616' })
    await expect(getProjectTrustControl(projectId, workspaceId, invoke)).rejects.toThrow()
  })

  it('rejects a root admission newer than its attached workspace', async () => {
    const invoke = vi.fn().mockResolvedValue({ ...snapshot, rootAdmissionVersion: '3' })
    await expect(getProjectTrustControl(projectId, workspaceId, invoke)).rejects.toThrow()
  })

  it('uses the closed desktop command contract without renderer confirmation or policy fields', async () => {
    const invoke = vi.fn().mockResolvedValue({ outcome: 'cancelled', snapshot: null })
    await expect(requestProjectTrustControl(projectId, workspaceId, 'confirm_project', invoke))
      .resolves.toEqual({ outcome: 'cancelled', snapshot: null })
    expect(invoke).toHaveBeenCalledWith('request_project_trust_control', {
      projectId, workspaceId, action: 'confirm_project',
    })
  })
})
