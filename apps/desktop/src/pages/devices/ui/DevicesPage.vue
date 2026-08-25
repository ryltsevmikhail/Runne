<script setup lang="ts">
import { isTauri } from '@tauri-apps/api/core'
import { onMounted, ref } from 'vue'

import type { SettingsPageAdapter } from '@/pages/settings'
import SettingsStatePage from '@/pages/settings/ui/SettingsStatePage.vue'
import type { RuntimeDeviceSnapshot } from '@/shared/api/platform/devices'
import { getDeviceStatus } from '@/shared/api/platform/devices'
import { translate } from '@/shared/i18n'

type LoadDeviceStatus = () => Promise<RuntimeDeviceSnapshot>

const props = defineProps<{
  readonly adapter?: SettingsPageAdapter
  readonly loadDeviceStatus?: LoadDeviceStatus
}>()

const status = ref<RuntimeDeviceSnapshot | null>(null)
const loading = ref(true)
const failed = ref(false)

async function loadStatus() {
  try {
    status.value = await (props.loadDeviceStatus ?? (async () => {
      if (!isTauri()) throw new Error('native device status unavailable')
      return getDeviceStatus()
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
  if (props.adapter === undefined) void loadStatus()
})
</script>

<template>
  <SettingsStatePage
    v-if="props.adapter !== undefined"
    title="Devices"
    title-key="settings.devices"
    :adapter="props.adapter"
  />
  <section v-else-if="loading" aria-live="polite">
    <h1>{{ translate('devices.loading') }}</h1>
  </section>
  <section v-else-if="failed || status === null" role="alert">
    <h1>{{ translate('devices.unavailable') }}</h1>
    <p>{{ translate('devices.unavailableMessage') }}</p>
  </section>
  <section v-else aria-labelledby="devices-title">
    <h1 id="devices-title">{{ translate('settings.devices') }}</h1>
    <dl>
      <div><dt>{{ translate('devices.thisDevice') }}</dt><dd>{{ status.authenticated ? translate('devices.authenticated') : translate('devices.notAuthenticated') }}</dd></div>
      <div><dt>{{ translate('devices.runtimeConnection') }}</dt><dd>{{ status.connection }}</dd></div>
      <div><dt>{{ translate('devices.runtimeVersion') }}</dt><dd>{{ status.runtimeVersion ?? translate('devices.unavailableValue') }}</dd></div>
      <div><dt>{{ translate('devices.launchGeneration') }}</dt><dd>{{ status.launchGeneration ?? translate('devices.unavailableValue') }}</dd></div>
    </dl>
  </section>
</template>
