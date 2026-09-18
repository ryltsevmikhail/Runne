import { isProviderId, type ProviderId } from '@/shared/api/platform/providerCatalog'

/** Units emitted by a provider or derived from local request accounting. */
export type ProviderQuotaUnit = 'credits' | 'requests' | 'tokens'
/** Provenance is explicit so missing provider data cannot look unlimited. */
export type ProviderQuotaSource = 'provider_reported' | 'local_usage' | 'unknown'
/** Strongest retained availability evidence; exhausted is never unlimited. */
export type ProviderQuotaAvailability = 'known' | 'exhausted' | 'stale' | 'unknown'

export type ProviderQuotaWindow = Readonly<{
  kind: string
  used: number | null
  limit: number | null
  remaining: number | null
  /** Provider percentage when absolute counters are unavailable. */
  percentUsed?: number | null
  resetAt: number | null
}>

/** Additive, renderer-safe quota projection; it carries no credential material. */
export type ProviderQuotaProjection = Readonly<{
  providerId: ProviderId
  source: ProviderQuotaSource
  unit: ProviderQuotaUnit | null
  used: number | null
  limit: number | null
  remaining: number | null
  /** Unix epoch seconds; null when the provider did not attest a reset time. */
  resetAt: number | null
  /** Unix epoch seconds for the observation. */
  observedAt: number
  availability: ProviderQuotaAvailability
  windows: readonly ProviderQuotaWindow[]
}>

const quotaKeys = ['providerId', 'source', 'unit', 'used', 'limit', 'remaining', 'resetAt', 'observedAt', 'availability', 'windows'] as const
const units: readonly ProviderQuotaUnit[] = ['credits', 'requests', 'tokens']
const sources: readonly ProviderQuotaSource[] = ['provider_reported', 'local_usage', 'unknown']
const availabilities: readonly ProviderQuotaAvailability[] = ['known', 'exhausted', 'stale', 'unknown']

/** Parses only the exact quota shape approved for future runtime projection. */
export function projectProviderQuotaSnapshot(value: unknown): ProviderQuotaProjection {
  if (!isRecord(value) || Object.keys(value).length !== quotaKeys.length || quotaKeys.some(key => !(key in value))) {
    throw new Error('Invalid provider quota projection')
  }
  const candidate = value as Record<keyof ProviderQuotaProjection, unknown>
  if (!isProviderId(candidate.providerId) || !isOneOf(candidate.source, sources)
    || !isOneOf(candidate.availability, availabilities) || !isWindows(candidate.windows)
    || !isNullableOneOf(candidate.unit, units) || !isNullableCounter(candidate.used)
    || !isNullableCounter(candidate.limit) || !isNullableCounter(candidate.remaining)
    || !isNullableReset(candidate.resetAt) || !isCounter(candidate.observedAt)
    || !isCoherentSource(candidate)) {
    throw new Error('Invalid provider quota projection')
  }
  return value as ProviderQuotaProjection
}

/** Returns fields safe to render; local usage never becomes provider remaining. */
export function trustedQuotaFields(snapshot: ProviderQuotaProjection): Pick<ProviderQuotaProjection, 'unit' | 'used' | 'limit' | 'remaining' | 'resetAt'> {
  if (snapshot.source === 'unknown') return { unit: null, used: null, limit: null, remaining: null, resetAt: null }
  if (snapshot.source === 'local_usage') return { unit: snapshot.unit, used: snapshot.used, limit: null, remaining: null, resetAt: null }
  return { unit: snapshot.unit, used: snapshot.used, limit: snapshot.limit, remaining: snapshot.remaining, resetAt: snapshot.resetAt }
}

function isCoherentSource(value: Record<keyof ProviderQuotaProjection, unknown>): boolean {
  if (value.source === 'unknown') return value.unit === null && value.used === null && value.limit === null
    && value.remaining === null && value.resetAt === null && value.availability === 'unknown'
    && (value.windows as readonly unknown[]).length === 0
  if (value.source === 'local_usage') return value.unit !== null && value.used !== null
    && value.limit === null && value.remaining === null && value.resetAt === null
    && value.availability !== 'exhausted' && (value.windows as readonly unknown[]).length === 0
  if ((value.unit === null && (value.windows as readonly unknown[]).length === 0)
    || (value.used === null && value.limit === null && value.remaining === null
      && (value.windows as readonly unknown[]).length === 0)) return false
  const limit = value.limit as number | null
  const used = value.used as number | null
  const remaining = value.remaining as number | null
  if (limit !== null && (used !== null && used > limit || remaining !== null && remaining > limit)) return false
  return true
}

function isWindows(value: unknown): value is readonly ProviderQuotaWindow[] {
  return Array.isArray(value) && value.every(window => {
    if (!isRecord(window) || !hasWindowKeys(window)
      || typeof window.kind !== 'string' || window.kind.length === 0 || window.kind.length > 64
      || !window.kind.split('').every(character => character.charCodeAt(0) >= 0x21 && character.charCodeAt(0) <= 0x7e)
      || !isNullableCounter(window.used) || !isNullableCounter(window.limit)
      || !hasValidPercent(window)
      || !isNullableCounter(window.remaining) || !isNullableReset(window.resetAt)) return false
    const limit = window.limit as number | null
    return limit === null || ((window.used === null || (window.used as number) <= limit)
      && (window.remaining === null || (window.remaining as number) <= limit))
  })
}

function hasWindowKeys(value: Record<string, unknown>): boolean {
  const required = ['kind', 'used', 'limit', 'remaining', 'resetAt']
  const keys = Object.keys(value)
  return (keys.length === required.length || keys.length === required.length + 1)
    && required.every(key => key in value)
    && (keys.length === required.length || 'percentUsed' in value)
}

function hasValidPercent(value: Record<string, unknown>): boolean {
  return !('percentUsed' in value) || isNullablePercent(value.percentUsed)
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isCounter(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
}

function isNullableCounter(value: unknown): value is number | null {
  return value === null || isCounter(value)
}

function isNullablePercent(value: unknown): value is number | null {
  return value === null
    || (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= 100)
}

function isNullableReset(value: unknown): value is number | null {
  return value === null || (isCounter(value) && value > 0)
}

function isOneOf<T extends string>(value: unknown, values: readonly T[]): value is T {
  return typeof value === 'string' && values.includes(value as T)
}

function isNullableOneOf<T extends string>(value: unknown, values: readonly T[]): value is T | null {
  return value === null || isOneOf(value, values)
}
