<script setup lang="ts">
import { isTauri } from '@tauri-apps/api/core'
import { onMounted, ref } from 'vue'

import { acquireRendererGeneration } from '@/entities/project'
import type { SettingsPageAdapter } from '@/pages/settings'
import SettingsStatePage from '@/pages/settings/ui/SettingsStatePage.vue'
import {
  enrollErrorCode,
  isQuotaRefreshSupported,
  providerCatalogEntry,
  quotaFor,
  quotaWindowSummaries,
  quotaSummary,
  readinessLabel,
  readinessSourceLabel,
} from '@/pages/providers/model/providerPageHelpers'
import {
  CREDENTIAL_PROVIDER_IDS,
  isCredentialProvider,
  isEnrollableProvider,
} from '@/shared/api/platform/providerCatalog'
import {
  getProviderCredentialEnrollmentStatus,
  getProviderCatalog,
  getProviderQuota,
  getProviderStatus,
  requestProviderCredentialIntent,
  type ProviderCredentialAction,
  type ProviderCredentialIntentDisposition,
  type ProviderCredentialProjection,
  type ProviderCredentialProvider,
  type ProviderStatusSnapshot,
  type ProviderCatalogSnapshot,
  type ProviderQuotaProjection,
} from '@/shared/api/platform/providers'
import { translate, type LocaleKey } from '@/shared/i18n'
import ProviderRow from './ProviderRow.vue'

type LoadProviderStatus = () => Promise<readonly ProviderStatusSnapshot[]>
type LoadProviderCatalog = () => Promise<readonly ProviderCatalogSnapshot[]>
type LoadProviderQuota = () => Promise<readonly ProviderQuotaProjection[]>
type LoadProviderCredentialEnrollmentStatus = (
  provider: ProviderCredentialProvider,
) => Promise<ProviderCredentialProjection>
type AcquireGeneration = () => Promise<number>
type RequestCredentialIntent = (
  provider: ProviderCredentialProvider,
  action: ProviderCredentialAction,
  expectedRevision: number,
  rendererGeneration: number,
) => Promise<ProviderCredentialIntentDisposition>

const props = defineProps<{
  readonly adapter?: SettingsPageAdapter
  readonly loadProviderStatus?: LoadProviderStatus
  readonly loadProviderCatalog?: LoadProviderCatalog
  readonly loadProviderQuota?: LoadProviderQuota
  readonly loadProviderCredentialEnrollmentStatus?: LoadProviderCredentialEnrollmentStatus
  readonly acquireGeneration?: AcquireGeneration
  readonly requestCredentialIntent?: RequestCredentialIntent
}>()

const statuses = ref<readonly ProviderStatusSnapshot[] | null>(null)
const catalog = ref<readonly ProviderCatalogSnapshot[] | null>(null)
const quotas = ref<readonly ProviderQuotaProjection[]>([])
const credentialStatuses = ref<Partial<Record<ProviderCredentialProvider, ProviderCredentialProjection>>>({})
const loading = ref(true)
const failed = ref(false)
const enrolling = ref<Partial<Record<ProviderCredentialProvider, boolean>>>({})
const enrollNotes = ref<Partial<Record<ProviderCredentialProvider, string | undefined>>>({})

let rendererGeneration: number | null = null
let statusLoadGeneration = 0

function invalidateQuotas(): void {
  statusLoadGeneration += 1
  quotas.value = []
}

async function currentRendererGeneration(acquire: AcquireGeneration): Promise<number> {
  rendererGeneration ??= await acquire()
  return rendererGeneration
}

async function defaultRequestCredentialIntent(
  provider: ProviderCredentialProvider,
  action: ProviderCredentialAction,
  expectedRevision: number,
  rendererGeneration: number,
): Promise<ProviderCredentialIntentDisposition> {
  if (!isTauri()) throw new Error('native provider credential intent unavailable')
  return requestProviderCredentialIntent(provider, action, expectedRevision, rendererGeneration)
}

async function loadStatuses() {
  const generation = ++statusLoadGeneration
  try {
    const loadStatus = props.loadProviderStatus ?? (async () => {
      if (!isTauri()) throw new Error('native provider status unavailable')
      return getProviderStatus()
    })
    const loadCatalog = props.loadProviderCatalog ?? (async () => {
      if (!isTauri()) return []
      return getProviderCatalog()
    })
    const nextStatuses = await loadStatus()
    if (generation !== statusLoadGeneration) return
    statuses.value = nextStatuses
    const nextCatalog = await loadCatalog()
    if (generation !== statusLoadGeneration) return
    catalog.value = nextCatalog
    const loadQuota = props.loadProviderQuota ?? (async () => {
      if (!isTauri()) return []
      return getProviderQuota()
    })
    const quotaResult = await Promise.allSettled([loadQuota()])
    if (generation !== statusLoadGeneration) return
    quotas.value = quotaResult[0]?.status === 'fulfilled' ? quotaResult[0].value : []
    await loadCredentialStatuses(generation)
  }
  catch {
    if (generation === statusLoadGeneration) {
      failed.value = true
      quotas.value = []
    }
  }
  finally {
    if (generation === statusLoadGeneration) loading.value = false
  }
}

function credentialLoader(): LoadProviderCredentialEnrollmentStatus {
  return props.loadProviderCredentialEnrollmentStatus ?? (async (provider) => {
    if (!isTauri()) throw new Error('native provider credential status unavailable')
    return getProviderCredentialEnrollmentStatus(provider)
  })
}

async function loadCredentialStatuses(generation: number) {
  const load = credentialLoader()
  const settled = await Promise.allSettled(CREDENTIAL_PROVIDER_IDS.map(async provider => [provider, await load(provider)] as const))
  if (generation !== statusLoadGeneration) return
  credentialStatuses.value = Object.fromEntries(settled.flatMap(result => result.status === 'fulfilled' ? [result.value] : []))
}

function credentialStatus(providerId: ProviderStatusSnapshot['providerId']) {
  return isCredentialProvider(providerId) ? credentialStatuses.value[providerId] : undefined
}

function isEnrolling(providerId: ProviderStatusSnapshot['providerId']): boolean {
  return isEnrollableProvider(providerId) && enrolling.value[providerId] === true
}

function enrollNote(providerId: ProviderStatusSnapshot['providerId']): string | undefined {
  return isEnrollableProvider(providerId) ? enrollNotes.value[providerId] : undefined
}

function hasCredential(providerId: ProviderStatusSnapshot['providerId']): boolean {
  return credentialStatus(providerId)?.credentialState === 'configured'
}

function credentialBusy(providerId: ProviderStatusSnapshot['providerId']): boolean {
  const status = credentialStatus(providerId)
  return isEnrolling(providerId) || status?.pendingOperation != null || status?.cleanupPending === true
}

async function expectedLifecycleRevision(provider: ProviderCredentialProvider, action: 'pair' | 'revoke' | 'verify'): Promise<number> {
  const known = credentialStatuses.value[provider]
  if (action === 'pair' && known !== undefined) return known.lifecycleRevision
  const fresh = await credentialLoader()(provider)
  credentialStatuses.value = { ...credentialStatuses.value, [provider]: fresh }
  if (action !== 'pair' && (fresh.credentialState !== 'configured'
    || fresh.readiness !== 'ready' || fresh.pendingOperation !== null || fresh.cleanupPending)) {
    throw { code: 'provider_credential_state_changed' }
  }
  return fresh.lifecycleRevision
}

async function changeCredential(providerId: ProviderStatusSnapshot['providerId'], action: 'pair' | 'revoke' | 'verify') {
  if (!isEnrollableProvider(providerId) || credentialBusy(providerId)) return
  if (action === 'revoke' && !hasCredential(providerId)) return
  if (action === 'verify' && (!isQuotaRefreshSupported(providerId) || !hasCredential(providerId))) return
  const provider: ProviderCredentialProvider = providerId
  invalidateQuotas()
  enrolling.value[provider] = true
  enrollNotes.value[provider] = undefined
  try {
    const generation = await currentRendererGeneration(props.acquireGeneration ?? acquireRendererGeneration)
    const expectedRevision = await expectedLifecycleRevision(provider, action)
    const request = props.requestCredentialIntent ?? defaultRequestCredentialIntent
    const disposition = await request(provider, action, expectedRevision, generation)
    if (disposition === 'completed') {
      enrollNotes.value[provider] = translate(action === 'verify'
        ? 'providers.quotaRefreshSucceeded'
        : action === 'revoke' ? 'providers.revokeSucceeded' : 'providers.enrollSucceeded')
      await loadStatuses()
    }
    else if (disposition === 'pending') {
      enrollNotes.value[provider] = translate(action === 'verify'
        ? 'providers.quotaRefreshPending'
        : action === 'revoke' ? 'providers.revokePending' : 'providers.enrollPending')
    }
    else {
      enrollNotes.value[provider] = translate(action === 'verify'
        ? 'providers.quotaRefreshFailed'
        : action === 'revoke' ? 'providers.revokeFailed' : 'providers.enrollFailed', { code: disposition })
    }
  }
  catch (error) {
    const code = enrollErrorCode(error)
    enrollNotes.value[provider] = action === 'verify'
      ? translate('providers.quotaRefreshFailed', { code })
      : action === 'revoke'
        ? translate('providers.revokeFailed', { code })
        : translate(enrollFailureKey(code), { code })
  }
  finally {
    enrolling.value[provider] = false
  }
}

function enrollFailureKey(code: string): LocaleKey {
  switch (code) {
    case 'provider_credential_service_approval_required':
      return 'providers.enrollFailed.approvalRequired'
    case 'provider_credential_service_not_found':
      return 'providers.enrollFailed.serviceNotFound'
    case 'provider_credential_service_unavailable':
      return 'providers.enrollFailed.serviceUnavailable'
    default:
      return 'providers.enrollFailed'
  }
}

onMounted(() => {
  if (props.adapter === undefined) void loadStatuses()
})

</script>

<template>
  <SettingsStatePage
    v-if="props.adapter !== undefined"
    title="Providers"
    title-key="settings.providers"
    :adapter="props.adapter"
  />
  <section
    v-else-if="loading"
    class="providers-page"
    aria-live="polite"
  >
    <h1>{{ translate('providers.loading') }}</h1>
  </section>
  <section
    v-else-if="failed || statuses === null || catalog === null"
    class="providers-page"
    role="alert"
  >
    <h1>{{ translate('providers.unavailable') }}</h1>
    <p>{{ translate('providers.unavailableMessage') }}</p>
  </section>
  <section
    v-else
    class="providers-page"
    aria-labelledby="providers-title"
  >
    <h1 id="providers-title">
      {{ translate('settings.providers') }}
    </h1>
    <ul>
      <ProviderRow
        v-for="status in statuses"
        :key="status.providerId"
        :status="status"
        :catalog="providerCatalogEntry(catalog, status.providerId)"
        :credential="credentialStatus(status.providerId)"
        :quota-summary="quotaSummary(quotas, status.providerId)"
        :quota-source="quotaFor(quotas, status.providerId)?.source"
        :quota-availability="quotaFor(quotas, status.providerId)?.availability"
        :quota-windows="quotaWindowSummaries(quotaFor(quotas, status.providerId))"
        :quota-refresh-supported="isQuotaRefreshSupported(status.providerId)"
        :readiness="readinessLabel(status, credentialStatus(status.providerId))"
        :readiness-source="readinessSourceLabel(status, credentialStatus(status.providerId))"
        :busy="credentialBusy(status.providerId)"
        :note="enrollNote(status.providerId)"
        @credential-action="changeCredential(status.providerId, $event)"
      />
    </ul>
  </section>
</template>
