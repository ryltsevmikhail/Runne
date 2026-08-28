import { describe, expect, it } from 'vitest'

import { projectProviderCredentialSnapshot } from './providerCredentialProjection'

const snapshot = {
  providerId: 'openai',
  credentialState: 'configured',
  readiness: 'ready',
  lifecycleRevision: 7,
  readinessRevision: 8,
  observedAt: 9,
  verificationState: 'local_verified',
  verificationRevision: 7,
  pendingOperation: null,
  cleanupPending: false,
  lastDisposition: 'completed',
} as const

describe('projectProviderCredentialSnapshot', () => {
  it('keeps exactly the safe V2 provider projection', () => {
    expect(projectProviderCredentialSnapshot(snapshot)).toEqual(snapshot)
  })

  it('rejects secret, authority, and native implementation metadata', () => {
    for (const prohibited of [
      'credential',
      'ticket',
      'secret',
      'version',
      'nativePath',
      'nativeError',
      'processIdentity',
      'releaseDigest',
    ]) {
      expect(() => projectProviderCredentialSnapshot({ ...snapshot, [prohibited]: 'opaque' }))
        .toThrow('Invalid provider credential projection')
    }
  })

  it('rejects invalid lifecycle fields and unknown closed values', () => {
    for (const invalid of [
      { ...snapshot, lifecycleRevision: 0 },
      { ...snapshot, readinessRevision: 0 },
      { ...snapshot, verificationRevision: -1 },
      { ...snapshot, observedAt: Number.NaN },
      { ...snapshot, credentialState: 'stale' },
      { ...snapshot, pendingOperation: 'native_write' },
    ]) {
      expect(() => projectProviderCredentialSnapshot(invalid))
        .toThrow('Invalid provider credential projection')
    }
  })
})
