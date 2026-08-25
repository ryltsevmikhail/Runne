import { describe, expect, it, vi } from 'vitest'

import { getApproval, listPendingApprovals } from './approvals'

const id = '018f2e3a-7000-7000-8000-000000000212'
const approval = { approvalId: id, taskRunId: id, attemptId: null, invocationId: id, action: 'fs:write', resource: 'workspace:/src/main.rs', actionDigest: '1'.repeat(64), policyRevision: 7, requestVersion: 3, expiresAt: 2_000, riskSummary: 'write source', state: 'pending' }

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
})
