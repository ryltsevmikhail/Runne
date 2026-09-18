import { translate, type LocaleKey } from '@/shared/i18n'
import {
  isCredentialProvider,
  providerDefinition,
  providerDisplayName,
} from '@/shared/api/platform/providerCatalog'
import { currentLocale } from '@/shared/model/locale'
import type {
  ProviderCatalogSnapshot,
  ProviderCredentialProjection,
  ProviderCredentialReadiness,
  ProviderReadiness,
  ProviderStatusSnapshot,
} from '@/shared/api/platform/providers'

import type { ProviderQuotaProjection, ProviderQuotaWindow } from './providerQuota'

export function providerCatalogEntry(
  catalog: readonly ProviderCatalogSnapshot[] | null,
  providerId: ProviderStatusSnapshot['providerId'],
): ProviderCatalogSnapshot | undefined {
  return catalog?.find(entry => entry.providerId === providerId)
}

export function quotaFor(
  quotas: readonly ProviderQuotaProjection[],
  providerId: ProviderStatusSnapshot['providerId'],
): ProviderQuotaProjection | undefined {
  return quotas.find(quota => quota.providerId === providerId)
}

export function readinessLabel(
  status: ProviderStatusSnapshot,
  credential: ProviderCredentialProjection | undefined,
): string {
  if (isCredentialProvider(status.providerId)) {
    return translate(credential === undefined
      ? 'providers.readiness.unavailable'
      : credentialReadinessKeys[credential.readiness])
  }
  return translate(runtimeReadinessKeys[status.readiness])
}

export function readinessSourceLabel(
  status: ProviderStatusSnapshot,
  credential: ProviderCredentialProjection | undefined,
): string {
  if (!isCredentialProvider(status.providerId)) return translate('providers.readinessSource.runtime')
  return translate(credential === undefined
    ? 'providers.readinessSource.unavailable'
    : 'providers.readinessSource.credential')
}

export function credentialActionLabel(providerId: ProviderStatusSnapshot['providerId'], configured = false): string {
  if (configured) return translate('providers.rotateCredential')
  return isManualOAuthProvider(providerId)
    ? translate('providers.importOAuthCredential')
    : translate('providers.enrollCredential')
}

export function isManualOAuthProvider(providerId: ProviderStatusSnapshot['providerId']): boolean {
  return providerId === 'openai-codex' || providerId === 'github-copilot'
}

export function quotaSummary(
  quotas: readonly ProviderQuotaProjection[],
  providerId: ProviderStatusSnapshot['providerId'],
): string | undefined {
  const quota = quotaFor(quotas, providerId)
  if (quota === undefined) return undefined
  if (quota.availability === 'exhausted') {
    return quota.resetAt === null
      ? translate('providers.quota.exhaustedUnknownReset')
      : translate('providers.quota.exhausted', { reset: formatQuotaDate(quota.resetAt) })
  }
  if (quota.availability === 'stale') {
    return translate('providers.quota.stale', { source: quotaSourceLabel(quota.source) })
  }
  if (quota.source === 'unknown') return translate('providers.quota.unknown')
  if (quota.source === 'local_usage') {
    return translate('providers.quota.localUsage', {
      used: quota.used ?? 0,
      unit: quota.unit === null ? '' : quotaUnitLabel(quota.unit),
    })
  }
  if (quota.remaining !== null && quota.limit !== null && quota.unit !== null) {
    return translate('providers.quota.known', {
      remaining: quota.remaining,
      limit: quota.limit,
      unit: quotaUnitLabel(quota.unit),
    })
  }
  return translate('providers.quota.knownUnknown')
}

export function quotaWindowSummaries(quota: ProviderQuotaProjection | undefined): readonly string[] {
  if (quota === undefined || quota.source !== 'provider_reported') return []
  return quota.windows.map(window => quotaWindowSummary(window, quota.unit))
}

function quotaWindowSummary(window: ProviderQuotaWindow, unit: ProviderQuotaProjection['unit']): string {
  const reset = window.resetAt === null ? translate('providers.quota.resetUnknown') : formatQuotaDate(window.resetAt)
  const label = quotaWindowLabel(window.kind)
  if (window.remaining !== null && window.limit !== null && unit !== null) {
    return translate('providers.quota.window', {
      window: label, remaining: window.remaining, limit: window.limit,
      unit: quotaUnitLabel(unit), reset,
    })
  }
  if (window.percentUsed !== undefined && window.percentUsed !== null) {
    return translate('providers.quota.windowPercentUsed', {
      window: label, percent: window.percentUsed, reset,
    })
  }
  return translate('providers.quota.windowUnknown', { window: label, reset })
}

function formatQuotaDate(unixSeconds: number): string {
  try {
    return new Intl.DateTimeFormat(currentLocale.value, {
      dateStyle: 'medium', timeStyle: 'short',
    }).format(new Date(unixSeconds * 1000))
  }
  catch {
    return translate('providers.quota.resetUnknown')
  }
}

function quotaSourceLabel(source: ProviderQuotaProjection['source']): string {
  return translate(quotaSourceKeys[source])
}

function quotaUnitLabel(unit: Exclude<ProviderQuotaProjection['unit'], null>): string {
  return translate(quotaUnitKeys[unit])
}

function quotaWindowLabel(kind: string): string {
  const key = quotaWindowKeys[kind] ?? 'providers.quota.windowGeneric'
  return translate(key)
}

const quotaSourceKeys: Record<ProviderQuotaProjection['source'], LocaleKey> = {
  provider_reported: 'providers.quota.source.providerReported',
  local_usage: 'providers.quota.source.localUsage',
  unknown: 'providers.quota.source.unknown',
}

const quotaUnitKeys: Record<Exclude<ProviderQuotaProjection['unit'], null>, LocaleKey> = {
  credits: 'providers.quota.unit.credits',
  requests: 'providers.quota.unit.requests',
  tokens: 'providers.quota.unit.tokens',
}

const quotaWindowKeys: Record<string, LocaleKey> = {
  FiveHourTime: 'providers.quota.windowFiveHour',
  WeeklyTime: 'providers.quota.windowWeekly',
  MonthlyTime: 'providers.quota.windowMonthly',
  TokenQuotaUnspecified: 'providers.quota.windowTokenQuotaUnspecified',
}

const runtimeReadinessKeys: Record<ProviderReadiness, LocaleKey> = {
  ready: 'providers.readiness.ready',
  credential_missing: 'providers.readiness.credential_missing',
  credential_access_denied: 'providers.readiness.credential_access_denied',
  credential_identity_mismatch: 'providers.readiness.credential_identity_mismatch',
  secure_store_unavailable: 'providers.readiness.secure_store_unavailable',
  not_selected: 'providers.readiness.not_selected',
}

const credentialReadinessKeys: Record<ProviderCredentialReadiness, LocaleKey> = {
  ready: 'providers.readiness.ready',
  missing: 'providers.readiness.missing',
  stale: 'providers.readiness.stale',
  unavailable: 'providers.readiness.unavailable',
  unsupported: 'providers.readiness.unsupported',
  access_denied: 'providers.readiness.access_denied',
  conflict: 'providers.readiness.conflict',
  invariant_failure: 'providers.readiness.invariant_failure',
}

export function providerCatalogDisplayName(providerId: ProviderStatusSnapshot['providerId']): string {
  return providerDisplayName(providerId)
}

export function providerHasSubscription(providerId: ProviderStatusSnapshot['providerId']): boolean {
  return providerDefinition(providerId)?.billing === 'subscription'
}

export function isQuotaRefreshSupported(providerId: ProviderStatusSnapshot['providerId']): boolean {
  return providerId === 'zai'
    || providerId === 'zai-coding-cn'
    || providerId === 'kimi-coding'
    || providerId === 'minimax'
    || providerId === 'minimax-cn'
}

export function enrollErrorCode(error: unknown): string {
  const code = (error as { code?: unknown } | null | undefined)?.code
  if (typeof code === 'string' && code.length > 0) return code
  if (error instanceof Error) return error.message
  try {
    return JSON.stringify(error)
  }
  catch {
    return String(error)
  }
}
