import { describe, expect, it } from 'vitest'

import { projectProviderQuotaSnapshot, trustedQuotaFields, type ProviderQuotaProjection } from './providerQuota'
import { quotaSummary, quotaWindowSummaries } from './providerPageHelpers'

const providerReported: ProviderQuotaProjection = {
  providerId: 'qwen-token-plan-individual', source: 'provider_reported', unit: 'credits',
  used: 250, limit: 1000, remaining: 750, resetAt: 1_700_000_000, observedAt: 1_699_999_000,
  availability: 'known', windows: [],
}

describe('provider quota projection', () => {
  it('preserves provider reported units, remaining, and reset metadata', () => {
    const projection = projectProviderQuotaSnapshot(providerReported)
    expect(trustedQuotaFields(projection)).toEqual({
      unit: 'credits', used: 250, limit: 1000, remaining: 750, resetAt: 1_700_000_000,
    })
  })

  it('keeps local usage distinct from provider remaining and limits', () => {
    const projection = projectProviderQuotaSnapshot({
      providerId: 'zai', source: 'local_usage', unit: 'requests', used: 4,
      limit: null, remaining: null, resetAt: null, observedAt: 12,
      availability: 'unknown', windows: [],
    })
    expect(trustedQuotaFields(projection)).toEqual({
      unit: 'requests', used: 4, limit: null, remaining: null, resetAt: null,
    })
  })

  it('does not represent unknown quota as zero or unlimited', () => {
    const projection = projectProviderQuotaSnapshot({
      providerId: 'zai', source: 'unknown', unit: null,
      used: null, limit: null, remaining: null, resetAt: null, observedAt: 0,
      availability: 'unknown', windows: [],
    })
    expect(trustedQuotaFields(projection)).toEqual({
      unit: null, used: null, limit: null, remaining: null, resetAt: null,
    })
  })

  it.each([
    { ...providerReported, token: 'secret' },
    { ...providerReported, providerId: 'unknown-provider' },
    { ...providerReported, source: 'unknown', unit: null, used: 0 },
    { ...providerReported, source: 'local_usage', limit: 1000, remaining: null, resetAt: null },
    { ...providerReported, limit: 100, remaining: 101 },
  ])('rejects non-closed or incoherent quota data: %j', invalid => {
    expect(() => projectProviderQuotaSnapshot(invalid)).toThrow('Invalid provider quota projection')
  })

  it('retains exhausted provider evidence when counters and unit are unknown', () => {
    const projection = projectProviderQuotaSnapshot({
      providerId: 'zai', source: 'provider_reported', unit: null,
      used: null, limit: null, remaining: null, resetAt: null, observedAt: 12,
      availability: 'exhausted', windows: [{
        kind: 'FiveHourTime', used: null, limit: null, remaining: 0, resetAt: 20,
      }],
    })
    expect(projection.availability).toBe('exhausted')
    expect(projection.windows[0]?.resetAt).toBe(20)
  })

  it('does not use an individual window reset as the aggregate resume time', () => {
    const projection = projectProviderQuotaSnapshot({
      providerId: 'zai', source: 'provider_reported', unit: null,
      used: null, limit: null, remaining: null, resetAt: null, observedAt: 12,
      availability: 'exhausted', windows: [{
        kind: 'FiveHourTime', used: null, limit: null, remaining: 0, resetAt: 20,
      }],
    })
    expect(quotaSummary([projection], 'zai')).toBe('Provider quota exhausted; aggregate reset is unknown')
  })

  it('accepts stale provider evidence without turning it into unknown', () => {
    const projection = projectProviderQuotaSnapshot({
      ...providerReported, availability: 'stale', observedAt: 12,
    })
    expect(projection.availability).toBe('stale')
    expect(trustedQuotaFields(projection).remaining).toBe(750)
  })

  it('renders provider source, unit, and a localized date without raw Unix time', () => {
    const summary = quotaSummary([providerReported], providerReported.providerId)
    expect(summary).toContain('Provider quota: 750/1000 credits')
    expect(summary).not.toContain('1700000000')
    expect(quotaWindowSummaries(providerReported)).toEqual([])
  })

  it('keeps every provider window visible while aggregate reset remains authoritative', () => {
    const projection = projectProviderQuotaSnapshot({
      providerId: 'zai', source: 'provider_reported', unit: 'requests',
      used: null, limit: null, remaining: null, resetAt: null, observedAt: 12,
      availability: 'exhausted', windows: [
        { kind: 'FiveHourTime', used: null, limit: 100, remaining: 0, resetAt: 20 },
        { kind: 'WeeklyTime', used: null, limit: 500, remaining: 10, resetAt: 30 },
      ],
    })
    expect(quotaSummary([projection], 'zai')).toBe('Provider quota exhausted; aggregate reset is unknown')
    expect(quotaWindowSummaries(projection)).toHaveLength(2)
    expect(quotaWindowSummaries(projection)[0]).toContain('Five-hour window')
    expect(quotaWindowSummaries(projection)[1]).toContain('Weekly window')
    expect(quotaWindowSummaries(projection).join(' ')).not.toContain('1700000000')
  })

  it.each([0, 50, 100])('preserves and renders a percentage-only Z.ai window at %i%%', percentUsed => {
    const projection = projectProviderQuotaSnapshot({
      providerId: 'zai', source: 'provider_reported', unit: null,
      used: null, limit: null, remaining: null, resetAt: null, observedAt: 12,
      availability: percentUsed === 100 ? 'exhausted' : 'unknown', windows: [{
        kind: 'TokenQuotaUnspecified', used: null, limit: null, remaining: null,
        percentUsed, resetAt: null,
      }],
    })

    expect(projection.windows[0]?.percentUsed).toBe(percentUsed)
    expect(quotaWindowSummaries(projection)[0]).toContain(`${percentUsed}%`)
    expect(quotaWindowSummaries(projection)[0]).not.toMatch(/tokens|credits|requests|\d+\/\d+/)
  })

  it('accepts a legacy window without percentUsed and rejects malformed percentages', () => {
    expect(projectProviderQuotaSnapshot({
      providerId: 'zai', source: 'provider_reported', unit: null,
      used: null, limit: null, remaining: null, resetAt: null, observedAt: 12,
      availability: 'unknown', windows: [{
        kind: 'WeeklyTime', used: null, limit: null, remaining: null, resetAt: null,
      }],
    }).windows[0]).not.toHaveProperty('percentUsed')
    for (const percentUsed of [-1, 101, 50.5, Number.NaN, Number.POSITIVE_INFINITY, '50', undefined]) {
      expect(() => projectProviderQuotaSnapshot({
        providerId: 'zai', source: 'provider_reported', unit: null,
        used: null, limit: null, remaining: null, resetAt: null, observedAt: 12,
        availability: 'unknown', windows: [{
          kind: 'WeeklyTime', used: null, limit: null, remaining: null, percentUsed, resetAt: null,
        }],
      })).toThrow('Invalid provider quota projection')
    }
  })

  it('labels stale provider evidence separately from local usage and unknown source', () => {
    const stale = projectProviderQuotaSnapshot({ ...providerReported, availability: 'stale', observedAt: 12 })
    const local = projectProviderQuotaSnapshot({
      providerId: 'zai', source: 'local_usage', unit: 'tokens', used: 8,
      limit: null, remaining: null, resetAt: null, observedAt: 12,
      availability: 'unknown', windows: [],
    })
    const unknown = projectProviderQuotaSnapshot({
      providerId: 'zai-coding-cn', source: 'unknown', unit: null,
      used: null, limit: null, remaining: null, resetAt: null, observedAt: 0,
      availability: 'unknown', windows: [],
    })
    expect(quotaSummary([stale], 'qwen-token-plan-individual')).toContain('stale (provider-reported)')
    expect(quotaSummary([local], 'zai')).toContain('Local usage (not provider quota): 8 tokens')
    expect(quotaSummary([unknown], 'zai-coding-cn')).toBe('Provider quota: unknown')
  })
})
