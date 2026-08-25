import { describe, expect, it } from 'vitest'

import { getProviderStatus, pairProviderCredential, revokeProviderCredential } from './providers'

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
  it('sends material as a one-shot command and returns only safe status', async () => {
    const invoke = async (command: string, args?: Record<string, unknown>) => {
      expect(command).toBe('pair_provider_credential')
      expect(args).toEqual({ provider: 'openai', credential: 'secret-value' })
      return { providerId: 'openai', status: 'configured' }
    }
    await expect(pairProviderCredential('openai', 'secret-value', invoke)).resolves.toEqual({
      providerId: 'openai',
      status: 'configured',
    })
  })

  it('rejects unsafe input and credential-shaped response leakage', async () => {
    await expect(pairProviderCredential('openai', 'line\nvalue', async () => ({}))).rejects.toThrow()
    await expect(revokeProviderCredential('deepseek', async () => ({
      providerId: 'deepseek', status: 'missing', credential: 'secret',
    }))).rejects.toThrow()
  })
})
