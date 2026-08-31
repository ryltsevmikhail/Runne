import { describe, expect, it, vi } from 'vitest'

import { decideApproval, getApproval, listPendingApprovals } from './approvals'

const id = '018f2e3a-7000-7000-8000-000000000212'
const approval = { approvalId: id, taskRunId: id, attemptId: null, invocationId: id, action: 'fs:write', resource: 'workspace:/src/main.rs', actionDigest: '1'.repeat(64), policyRevision: 7, requestVersion: 3, expiresAt: 2_000, riskSummary: 'write source', state: 'pending' as const }

describe('approval adapter', () => {
  it('accepts only the exact renderer-safe summary', async () => {
    const invoke = vi.fn().mockResolvedValue([approval])
    await expect(listPendingApprovals(invoke)).resolves.toEqual([approval])
    await expect(getApproval(id, vi.fn().mockResolvedValue(approval))).resolves.toEqual(approval)
  })

  it('rejects missing fields, control text and wrong identity', async () => {
    await expect(listPendingApprovals(vi.fn().mockResolvedValue([{ ...approval, extra: true }]))).rejects.toThrow()
    await expect(listPendingApprovals(vi.fn().mockResolvedValue([{ ...approval, action: 'bad\nvalue' }]))).rejects.toThrow()
    await expect(getApproval(id, vi.fn().mockResolvedValue({ ...approval, approvalId: id.replace('212', '213') }))).rejects.toThrow()
  })

  it('submits the exact version-bound decision and validates the acknowledgement', async () => {
    const invoke = vi.fn(async (command: string) => {
      if (command === 'prepare_approval_decision') return 'a'.repeat(64)
      return { approvalId: id, taskRunId: id, newVersion: 4, state: 'approved' }
    })

    await expect(decideApproval(approval, 'approve', 8, invoke)).resolves.toEqual({
      approvalId: id,
      taskRunId: id,
      newVersion: 4,
      state: 'approved',
    })
    expect(invoke).toHaveBeenCalledWith('prepare_approval_decision', {
      request: {
        approvalId: id,
        expectedVersion: 3,
        decision: 'approve',
        actionDigest: '1'.repeat(64),
        policyRevision: 7,
        rendererGeneration: 8,
      },
    })
    expect(invoke).toHaveBeenCalledWith(
      'consume_approval_decision',
      expect.objectContaining({ intent: 'a'.repeat(64) }),
    )
    expect(invoke).not.toHaveBeenCalledWith('respond_to_approval', expect.anything())
  })

  it('fails closed before consume when prepare does not return an opaque intent', async () => {
    const invoke = vi.fn().mockResolvedValue('not-an-intent')
    await expect(decideApproval(approval, 'approve', 8, invoke)).rejects.toThrow('Invalid approval intent')
    expect(invoke).toHaveBeenCalledTimes(1)
  })
})
