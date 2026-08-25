import { describe, expect, it } from 'vitest'

import { loadPendingExternalActivation, parseActivationTarget } from './external-activation'

const id = '018f2e3a-7000-7000-8000-000000000212'
const target = { runtime: 'gocode-local-runtime/2', projectId: null, workspaceId: null, taskRunId: id, approvalId: null, event: 'approval' }

describe('external activation', () => {
  it('accepts only the exact host DTO and keeps opaque identities', () => {
    expect(parseActivationTarget(target)).toEqual(target)
    expect(parseActivationTarget({ ...target, token: 'secret' })).toBeNull()
  })

  it('rejects malformed identity, runtime and empty targets', () => {
    expect(parseActivationTarget({ ...target, taskRunId: '1' })).toBeNull()
    expect(parseActivationTarget({ ...target, runtime: '../secret' })).toBeNull()
    expect(parseActivationTarget({ ...target, taskRunId: null })).toBeNull()
  })

  it('loads a pending activation through typed IPC', async () => {
    const value = await loadPendingExternalActivation(async command => {
      expect(command).toBe('get_pending_external_activation')
      return target
    })
    expect(value).toEqual(target)
  })
})
