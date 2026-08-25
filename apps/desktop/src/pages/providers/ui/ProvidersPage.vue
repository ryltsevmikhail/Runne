<script setup lang="ts">
import { isTauri } from '@tauri-apps/api/core'
import { onMounted, reactive, ref } from 'vue'

import type { SettingsPageAdapter } from '@/pages/settings'
import SettingsStatePage from '@/pages/settings/ui/SettingsStatePage.vue'
import {
  getProviderStatus,
  pairProviderCredential,
  revokeProviderCredential,
  type ProviderCredentialProvider,
  type ProviderStatusSnapshot,
} from '@/shared/api/platform/providers'
import { translate } from '@/shared/i18n'

type LoadProviderStatus = () => Promise<readonly ProviderStatusSnapshot[]>

const props = defineProps<{
  readonly adapter?: SettingsPageAdapter
  readonly loadProviderStatus?: LoadProviderStatus
}>()

const statuses = ref<readonly ProviderStatusSnapshot[] | null>(null)
const loading = ref(true)
const failed = ref(false)
const credentialDrafts = reactive<Record<ProviderCredentialProvider, string>>({ openai: '', deepseek: '' })
const busyProvider = ref<ProviderCredentialProvider | null>(null)
const mutationError = ref(false)

async function loadStatuses() {
  try {
    statuses.value = await (props.loadProviderStatus ?? (async () => {
      if (!isTauri()) throw new Error('native provider status unavailable')
      return getProviderStatus()
    }))()
  }
  catch {
    failed.value = true
  }
  finally {
    loading.value = false
  }
}

onMounted(() => {
  if (props.adapter === undefined) void loadStatuses()
})

function isCredentialProvider(provider: ProviderStatusSnapshot['providerId']): provider is ProviderCredentialProvider {
  return provider === 'openai' || provider === 'deepseek'
}

async function pair(provider: ProviderStatusSnapshot['providerId']) {
  if (!isCredentialProvider(provider) || !isTauri()) return
  mutationError.value = false
  busyProvider.value = provider
  try {
    await pairProviderCredential(provider, credentialDrafts[provider])
    credentialDrafts[provider] = ''
    statuses.value = await getProviderStatus()
  }
  catch {
    mutationError.value = true
  }
  finally {
    busyProvider.value = null
  }
}

async function revoke(provider: ProviderStatusSnapshot['providerId']) {
  if (!isCredentialProvider(provider) || !isTauri()) return
  mutationError.value = false
  busyProvider.value = provider
  try {
    await revokeProviderCredential(provider)
    statuses.value = await getProviderStatus()
  }
  catch {
    mutationError.value = true
  }
  finally {
    busyProvider.value = null
  }
}
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
    <p v-if="mutationError" role="alert">{{ translate('providers.mutationFailed') }}</p>
    <ul>
      <li v-for="status in statuses" :key="status.providerId">
        <strong>{{ status.providerId }}</strong>
        <span>{{ status.selected ? translate('providers.selected') : translate('providers.notSelected') }}</span>
        <span>{{ status.readiness }}</span>
        <template v-if="isCredentialProvider(status.providerId)">
          <label :for="`credential-${status.providerId}`">{{ translate('providers.credentialLabel') }}</label>
          <input
            :id="`credential-${status.providerId}`"
            v-model="credentialDrafts[status.providerId]"
            type="password"
            autocomplete="new-password"
            :aria-label="translate('providers.credentialLabel')"
          >
          <button
            type="button"
            :disabled="busyProvider !== null || credentialDrafts[status.providerId].length === 0"
            @click="void pair(status.providerId)"
          >{{ translate('providers.pair') }}</button>
          <button
            type="button"
            :disabled="busyProvider !== null"
            @click="void revoke(status.providerId)"
          >{{ translate('providers.revoke') }}</button>
        </template>
      </li>
    </ul>
  </section>
</template>
