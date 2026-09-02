import { describe, expect, it } from 'vitest'

import {
  getProviderCredentialEnrollmentStatus,
  getProviderStatus,
  projectProviderCredentialSnapshot,
  requestProviderCredentialIntent,
} from './providers'

const openai = {
  providerId: 'openai',
  mode: 'openai_responses_text_v1',
  profileId: 'openai-responses-text-v1',
  profileDigest: '1'.repeat(64),
  readiness: 'ready',
  selected: true,
} as const

const notSelected = {
  providerId: 'deepseek',
  mode: 'deepseek_responses_text_v1',
  profileId: 'deepseek-responses-text-v1',
  profileDigest: '2'.repeat(64),
  readiness: 'not_selected',
  selected: false,
} as const

const credentialProjection = {
  providerId: 'openai', credentialState: 'configured', readiness: 'ready', lifecycleRevision: 7,
  readinessRevision: 8, observedAt: 9, verificationState: 'local_verified', verificationRevision: 7,
  pendingOperation: null, cleanupPending: false, lastDisposition: 'completed',
} as const

describe('getProviderStatus', () => {
  it('accepts the closed owner projection', async () => {
    await expect(getProviderStatus(async () => [openai, notSelected])).resolves.toEqual([openai, notSelected])
  })

  it('rejects unknown fields and ambiguous selection', async () => {
    await expect(getProviderStatus(async () => [{ ...openai, token: 'secret' }])).rejects.toThrow()
    await expect(getProviderStatus(async () => [openai, { ...notSelected, selected: true, readiness: 'ready' }])).rejects.toThrow()
  })
})

describe('provider credential mutations', () => {
  it('sends only a pairing intent, never renderer credential material', async () => {
    const invoke = async (command: string, args?: Record<string, unknown>) => {
      expect(command).toBe('request_provider_credential_intent')
      expect(args).toEqual({ request: { provider: 'openai', action: 'pair', expectedRevision: 7, rendererGeneration: 4 } })
      return 'pending'
    }
    await expect(requestProviderCredentialIntent('openai', 'pair', 7, 4, invoke)).resolves.toBe('pending')
  })

  it('rejects invalid revision, renderer generation, and credential-shaped response leakage', async () => {
    await expect(requestProviderCredentialIntent('openai', 'pair', 0, 4, async () => ({}))).rejects.toThrow()
    for (const rendererGeneration of [0, -1, 1.5, Number.NaN, Number.MAX_SAFE_INTEGER + 1]) {
      await expect(requestProviderCredentialIntent('openai', 'pair', 1, rendererGeneration, async () => 'pending'))
        .rejects.toThrow('Invalid renderer generation')
    }
    await expect(requestProviderCredentialIntent('deepseek', 'pair', 1, 4, async () => ({ credential: 'secret' }))).rejects.toThrow()
  })
})

describe('provider credential enrollment status', () => {
  it('keeps exactly the safe V2 projection', () => {
    expect(projectProviderCredentialSnapshot(credentialProjection)).toEqual(credentialProjection)
  })

  it('requests one provider and keeps only the closed V2 renderer projection', async () => {
    const invoke = async (command: string, args?: Record<string, unknown>) => {
      expect(command).toBe('get_provider_credential_enrollment_status')
      expect(args).toEqual({ provider: 'openai' })
      return credentialProjection
    }
    await expect(getProviderCredentialEnrollmentStatus('openai', invoke)).resolves.toEqual(credentialProjection)
  })

  it('rejects secret-shaped V2 responses', async () => {
    await expect(getProviderCredentialEnrollmentStatus('deepseek', async () => ({
      ...credentialProjection, providerId: 'deepseek', ticket: 'secret',
    }))).rejects.toThrow('Invalid provider credential projection')
  })

  it('rejects native metadata and invalid closed values', () => {
    for (const invalid of [
      { ...credentialProjection, nativePath: '/credential-store' },
      { ...credentialProjection, lifecycleRevision: 0 },
      { ...credentialProjection, readinessRevision: 0 },
      { ...credentialProjection, verificationRevision: -1 },
      { ...credentialProjection, observedAt: Number.NaN },
      { ...credentialProjection, credentialState: 'stale' },
      { ...credentialProjection, pendingOperation: 'native_write' },
    ]) {
      expect(() => projectProviderCredentialSnapshot(invalid)).toThrow('Invalid provider credential projection')
    }
  })
})
