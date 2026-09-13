<script setup lang="ts">
import { isTauri } from '@tauri-apps/api/core'
import { onMounted, ref } from 'vue'

import { acquireRendererGeneration } from '@/entities/project'
import type { SettingsPageAdapter } from '@/pages/settings'
import SettingsStatePage from '@/pages/settings/ui/SettingsStatePage.vue'
import {
  getProviderCredentialEnrollmentStatus,
  getProviderStatus,
  requestProviderCredentialIntent,
  type ProviderCredentialAction,
  type ProviderCredentialIntentDisposition,
  type ProviderCredentialProjection,
  type ProviderCredentialProvider,
  type ProviderStatusSnapshot,
} from '@/shared/api/platform/providers'
import { translate } from '@/shared/i18n'

type LoadProviderStatus = () => Promise<readonly ProviderStatusSnapshot[]>
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
  readonly loadProviderCredentialEnrollmentStatus?: LoadProviderCredentialEnrollmentStatus
  readonly acquireGeneration?: AcquireGeneration
  readonly requestCredentialIntent?: RequestCredentialIntent
}>()

const statuses = ref<readonly ProviderStatusSnapshot[] | null>(null)
const credentialStatuses = ref<Partial<Record<ProviderCredentialProvider, ProviderCredentialProjection>>>({})
const loading = ref(true)
const failed = ref(false)
const enrolling = ref<Partial<Record<ProviderCredentialProvider, boolean>>>({})
const enrollNotes = ref<Partial<Record<ProviderCredentialProvider, string | undefined>>>({})

let rendererGeneration: number | null = null

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
  try {
    statuses.value = await (props.loadProviderStatus ?? (async () => {
      if (!isTauri()) throw new Error('native provider status unavailable')
      return getProviderStatus()
    }))()
    await loadCredentialStatuses()
  }
  catch {
    failed.value = true
  }
  finally {
    loading.value = false
  }
}

function credentialLoader(): LoadProviderCredentialEnrollmentStatus {
  return props.loadProviderCredentialEnrollmentStatus ?? (async (provider) => {
    if (!isTauri()) throw new Error('native provider credential status unavailable')
    return getProviderCredentialEnrollmentStatus(provider)
  })
}

async function loadCredentialStatuses() {
  const load = credentialLoader()
  const providers: readonly ProviderCredentialProvider[] = ['openai', 'deepseek']
  const settled = await Promise.allSettled(providers.map(async provider => [provider, await load(provider)] as const))
  credentialStatuses.value = Object.fromEntries(settled.flatMap(result => result.status === 'fulfilled' ? [result.value] : []))
}

function credentialStatus(providerId: ProviderStatusSnapshot['providerId']) {
  return providerId === 'openai' || providerId === 'deepseek' ? credentialStatuses.value[providerId] : undefined
}

function isCredentialProvider(providerId: ProviderStatusSnapshot['providerId']): providerId is ProviderCredentialProvider {
  return providerId === 'openai' || providerId === 'deepseek'
}

function isEnrolling(providerId: ProviderStatusSnapshot['providerId']): boolean {
  return isCredentialProvider(providerId) && enrolling.value[providerId] === true
}

function enrollNote(providerId: ProviderStatusSnapshot['providerId']): string | undefined {
  return isCredentialProvider(providerId) ? enrollNotes.value[providerId] : undefined
}

function hasCredential(providerId: ProviderStatusSnapshot['providerId']): boolean {
  return credentialStatus(providerId)?.credentialState === 'configured'
}

function credentialBusy(providerId: ProviderStatusSnapshot['providerId']): boolean {
  const status = credentialStatus(providerId)
  return isEnrolling(providerId) || status?.pendingOperation != null || status?.cleanupPending === true
}

function pairLabel(providerId: ProviderStatusSnapshot['providerId']): string {
  return translate(hasCredential(providerId) ? 'providers.rotateCredential' : 'providers.enrollCredential')
}

async function expectedLifecycleRevision(provider: ProviderCredentialProvider, action: 'pair' | 'revoke'): Promise<number> {
  const known = credentialStatuses.value[provider]
  if (action === 'pair' && known !== undefined) return known.lifecycleRevision
  const fresh = await credentialLoader()(provider)
  credentialStatuses.value = { ...credentialStatuses.value, [provider]: fresh }
  if (action === 'revoke' && (fresh.credentialState !== 'configured' || fresh.pendingOperation !== null || fresh.cleanupPending)) {
    throw { code: 'provider_credential_state_changed' }
  }
  return fresh.lifecycleRevision
}

function enrollErrorCode(error: unknown): string {
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

async function changeCredential(providerId: ProviderStatusSnapshot['providerId'], action: 'pair' | 'revoke') {
  if (!isCredentialProvider(providerId) || credentialBusy(providerId)) return
  if (action === 'revoke' && !hasCredential(providerId)) return
  const provider: ProviderCredentialProvider = providerId
  enrolling.value[provider] = true
  enrollNotes.value[provider] = undefined
  try {
    const generation = await currentRendererGeneration(props.acquireGeneration ?? acquireRendererGeneration)
    const expectedRevision = await expectedLifecycleRevision(provider, action)
    const request = props.requestCredentialIntent ?? defaultRequestCredentialIntent
    const disposition = await request(provider, action, expectedRevision, generation)
    if (disposition === 'completed') {
      enrollNotes.value[provider] = translate(action === 'revoke' ? 'providers.revokeSucceeded' : 'providers.enrollSucceeded')
      await loadStatuses()
    }
    else if (disposition === 'pending') {
      enrollNotes.value[provider] = translate(action === 'revoke' ? 'providers.revokePending' : 'providers.enrollPending')
    }
    else {
      enrollNotes.value[provider] = translate(action === 'revoke' ? 'providers.revokeFailed' : 'providers.enrollFailed', { code: disposition })
    }
  }
  catch (error) {
    enrollNotes.value[provider] = translate(action === 'revoke' ? 'providers.revokeFailed' : 'providers.enrollFailed', {
      code: enrollErrorCode(error),
    })
  }
  finally {
    enrolling.value[provider] = false
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
  <section v-else-if="loading" aria-live="polite">
    <h1>{{ translate('providers.loading') }}</h1>
  </section>
  <section v-else-if="failed || statuses === null" role="alert">
    <h1>{{ translate('providers.unavailable') }}</h1>
    <p>{{ translate('providers.unavailableMessage') }}</p>
  </section>
  <section v-else aria-labelledby="providers-title">
    <h1 id="providers-title">{{ translate('settings.providers') }}</h1>
    <ul>
      <li v-for="status in statuses" :key="status.providerId">
        <strong>{{ status.providerId }}</strong>
        <span>{{ status.selected ? translate('providers.selected') : translate('providers.notSelected') }}</span>
        <span>{{ status.readiness }}</span>
        <span v-if="credentialStatus(status.providerId) !== undefined">
          {{ credentialStatus(status.providerId)?.readiness }}
          {{ credentialStatus(status.providerId)?.verificationState }}
        </span>
        <template v-if="isCredentialProvider(status.providerId)">
          <button
            type="button"
            :aria-label="`${pairLabel(status.providerId)} (${status.providerId})`"
            :disabled="credentialBusy(status.providerId)"
            @click="changeCredential(status.providerId, 'pair')"
          >
            {{ pairLabel(status.providerId) }}
          </button>
          <button
            v-if="hasCredential(status.providerId)"
            type="button"
            :aria-label="`${translate('providers.revokeCredential')} (${status.providerId})`"
            :disabled="credentialBusy(status.providerId)"
            @click="changeCredential(status.providerId, 'revoke')"
          >
            {{ translate('providers.revokeCredential') }}
          </button>
          <span
            v-if="enrollNote(status.providerId)"
            role="status"
          >{{ enrollNote(status.providerId) }}</span>
        </template>
      </li>
    </ul>
  </section>
</template>
