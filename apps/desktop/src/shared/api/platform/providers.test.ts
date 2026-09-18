import { describe, expect, it } from 'vitest'

import {
  getProviderCredentialEnrollmentStatus,
  getProviderCatalog,
  getProviderQuota,
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

  it('accepts catalog entries for planned Z.ai and Qwen plans while keeping the schema closed', async () => {
    const planned = ['zai', 'zai-coding-cn', 'qwen-token-plan', 'qwen-token-plan-cn'].map((providerId, index) => ({
      providerId, mode: `planned_${index}`, profileId: `planned-${index}`, profileDigest: `${index + 3}`.repeat(64),
      readiness: 'not_selected', selected: false,
    }))
    await expect(getProviderStatus(async () => [openai, ...planned])).resolves.toHaveLength(5)
    await expect(getProviderStatus(async () => [{ ...openai, providerId: 'unlisted-provider' }])).rejects.toThrow()
  })
})

describe('getProviderCatalog', () => {
  it('accepts the closed backend projection and rejects secret fields', async () => {
    const catalog = [{
      providerId: 'zai', displayName: 'Z.AI', protocol: 'chat_completions', authOptions: ['api_key'],
      quota: 'subscription_window', implementation: 'catalog_only',
    }]
    await expect(getProviderCatalog(async command => {
      expect(command).toBe('get_provider_catalog')
      return catalog
    })).resolves.toEqual(catalog)
    await expect(getProviderCatalog(async () => [{ ...catalog[0], secret: 'token' }])).rejects.toThrow()
  })
})

describe('getProviderQuota', () => {
  it('accepts provider reported, local, and unknown evidence without secrets', async () => {
    const projections = [
      { providerId: 'zai', source: 'provider_reported', unit: 'credits', used: 25, limit: 100, remaining: 75, resetAt: 1_700_000_000, observedAt: 1_700_000_001, availability: 'known', windows: [] },
      { providerId: 'qwen-token-plan', source: 'local_usage', unit: 'tokens', used: 25, limit: null, remaining: null, resetAt: null, observedAt: 1_700_000_001, availability: 'unknown', windows: [] },
      { providerId: 'openrouter', source: 'unknown', unit: null, used: null, limit: null, remaining: null, resetAt: null, observedAt: 0, availability: 'unknown', windows: [] },
    ] as const
    await expect(getProviderQuota(async command => {
      expect(command).toBe('get_provider_quota')
      return projections
    })).resolves.toEqual(projections)
  })

  it('rejects secret fields and fabricated unknown remaining', async () => {
    await expect(getProviderQuota(async () => [{
      providerId: 'zai', source: 'unknown', unit: null, used: null, limit: null,
      remaining: 0, resetAt: null, observedAt: 0,
      availability: 'unknown', windows: [],
    }])).rejects.toThrow('Invalid provider quota projection')
    await expect(getProviderQuota(async () => [{
      providerId: 'zai', source: 'unknown', unit: null, used: null, limit: null,
      remaining: null, resetAt: null, observedAt: 0, token: 'secret',
      availability: 'unknown', windows: [],
    }])).rejects.toThrow('Invalid provider quota projection')
  })
})

describe('provider credential mutations', () => {
  it('sends remote verification as a separate native intent', async () => {
    const invoke = async (command: string, args?: Record<string, unknown>) => {
      expect(command).toBe('request_provider_credential_intent')
      expect(args).toEqual({
        request: {
          provider: 'zai', action: 'verify', verificationKind: 'remote',
          expectedRevision: 7, rendererGeneration: 4,
        },
      })
      return 'completed'
    }
    await expect(requestProviderCredentialIntent('zai', 'verify', 7, 4, invoke)).resolves.toBe('completed')
  })

  it('sends only a pairing intent, never renderer credential material', async () => {
    const invoke = async (command: string, args?: Record<string, unknown>) => {
      expect(command).toBe('request_provider_credential_intent')
      expect(args).toEqual({ request: { provider: 'openai', action: 'pair', expectedRevision: 7, rendererGeneration: 4 } })
      return 'pending'
    }
    await expect(requestProviderCredentialIntent('openai', 'pair', 7, 4, invoke)).resolves.toBe('pending')
  })

  it('accepts every backend disposition including completed and rejects unknown strings', async () => {
    for (const disposition of ['pending', 'completed', 'cancelled', 'unavailable'] as const) {
      await expect(requestProviderCredentialIntent('openai', 'pair', 7, 4, async () => disposition))
        .resolves.toBe(disposition)
    }
    await expect(requestProviderCredentialIntent('openai', 'pair', 7, 4, async () => 'ok'))
      .rejects.toThrow('Invalid provider credential intent disposition')
    await expect(requestProviderCredentialIntent('openai', 'pair', 7, 4, async () => ({ disposition: 'completed' })))
      .rejects.toThrow('Invalid provider credential intent disposition')
  })

  it('rejects invalid revision, renderer generation, and credential-shaped response leakage', async () => {
    await expect(requestProviderCredentialIntent('openai', 'pair', 0, 4, async () => ({}))).rejects.toThrow()
    for (const rendererGeneration of [0, -1, 1.5, Number.NaN, Number.MAX_SAFE_INTEGER + 1]) {
      await expect(requestProviderCredentialIntent('openai', 'pair', 1, rendererGeneration, async () => 'pending'))
        .rejects.toThrow('Invalid renderer generation')
    }
    await expect(requestProviderCredentialIntent('deepseek', 'pair', 1, 4, async () => ({ credential: 'secret' }))).rejects.toThrow()
    await expect(requestProviderCredentialIntent('unknown-provider' as never, 'pair', 1, 4, async () => 'pending'))
      .rejects.toThrow('Invalid provider credential provider')
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
    expect(() => projectProviderCredentialSnapshot({ ...credentialProjection, providerId: 'zai' }))
      .not.toThrow()
  })
})
