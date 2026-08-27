<script setup lang="ts">
import { isTauri } from '@tauri-apps/api/core'
import { onMounted, ref } from 'vue'

import type { SettingsPageAdapter } from '@/pages/settings'
import SettingsStatePage from '@/pages/settings/ui/SettingsStatePage.vue'
import {
  getProviderStatus,
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
      </li>
    </ul>
  </section>
</template>
