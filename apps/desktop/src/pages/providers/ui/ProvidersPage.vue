<script setup lang="ts">
import { isTauri } from '@tauri-apps/api/core'
import { onMounted, ref } from 'vue'

import type { SettingsPageAdapter } from '@/pages/settings'
import SettingsStatePage from '@/pages/settings/ui/SettingsStatePage.vue'
import {
  getProviderCredentialEnrollmentStatus,
  getProviderStatus,
  type ProviderCredentialProjection,
  type ProviderCredentialProvider,
  type ProviderStatusSnapshot,
} from '@/shared/api/platform/providers'
import { translate } from '@/shared/i18n'

type LoadProviderStatus = () => Promise<readonly ProviderStatusSnapshot[]>
type LoadProviderCredentialEnrollmentStatus = (
  provider: ProviderCredentialProvider,
) => Promise<ProviderCredentialProjection>

const props = defineProps<{
  readonly adapter?: SettingsPageAdapter
  readonly loadProviderStatus?: LoadProviderStatus
  readonly loadProviderCredentialEnrollmentStatus?: LoadProviderCredentialEnrollmentStatus
}>()

const statuses = ref<readonly ProviderStatusSnapshot[] | null>(null)
const credentialStatuses = ref<Partial<Record<ProviderCredentialProvider, ProviderCredentialProjection>>>({})
const loading = ref(true)
const failed = ref(false)

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

async function loadCredentialStatuses() {
  const load = props.loadProviderCredentialEnrollmentStatus ?? (async (provider) => {
    if (!isTauri()) throw new Error('native provider credential status unavailable')
    return getProviderCredentialEnrollmentStatus(provider)
  })
  const providers: readonly ProviderCredentialProvider[] = ['openai', 'deepseek']
  const settled = await Promise.allSettled(providers.map(async provider => [provider, await load(provider)] as const))
  credentialStatuses.value = Object.fromEntries(settled.flatMap(result => result.status === 'fulfilled' ? [result.value] : []))
}

function credentialStatus(providerId: ProviderStatusSnapshot['providerId']) {
  return providerId === 'openai' || providerId === 'deepseek' ? credentialStatuses.value[providerId] : undefined
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
      </li>
    </ul>
  </section>
</template>
