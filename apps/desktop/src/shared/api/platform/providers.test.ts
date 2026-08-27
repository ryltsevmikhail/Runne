import { describe, expect, it } from 'vitest'

import { getProviderStatus, requestProviderCredentialIntent } from './providers'

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
      expect(args).toEqual({ request: { provider: 'openai', action: 'pair', expectedRevision: 7 } })
      return 'pending'
    }
    await expect(requestProviderCredentialIntent('openai', 'pair', 7, invoke)).resolves.toBe('pending')
  })

  it('rejects invalid revision and credential-shaped response leakage', async () => {
    await expect(requestProviderCredentialIntent('openai', 'pair', 0, async () => ({}))).rejects.toThrow()
    await expect(requestProviderCredentialIntent('deepseek', 'pair', 1, async () => ({ credential: 'secret' }))).rejects.toThrow()
  })
})
