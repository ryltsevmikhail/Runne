<script setup lang="ts">
import { GcAlert, GcBadge } from '@runne/product/shared/ui'
import { isTauri } from '@tauri-apps/api/core'
import { computed, onMounted, ref } from 'vue'

import type { BootstrapState } from '@/shared/api/platform/bootstrap'
import { loadBootstrap } from '@/shared/api/platform/bootstrap'
import { translate } from '@/shared/i18n'

type LoadRuntime = () => Promise<BootstrapState>

const props = withDefaults(defineProps<{
  loadRuntime?: LoadRuntime
}>(), {
  loadRuntime: async (): Promise<BootstrapState> => isTauri()
    ? loadBootstrap()
    : {
        theme: 'dark',
        runtimeMode: 'bundled',
        runtime: 'unconfigured',
        runtimeLifecycle: 'starting',
        runtimeFailure: null,
      },
})

const runtime = ref<BootstrapState | null>(null)
const unavailable = ref(false)

const bundled = computed(() => runtime.value?.runtimeMode === 'bundled')

onMounted(async () => {
  try {
    runtime.value = await props.loadRuntime()
  }
  catch {
    unavailable.value = true
  }
})
</script>

<template>
  <section aria-labelledby="runtime-settings-title">
    <header class="page-header">
      <div>
        <h1 id="runtime-settings-title">
          {{ translate('runtimeSettings.title') }}
        </h1>
        <p>{{ translate('runtimeSettings.description') }}</p>
      </div>
    </header>
    <nav class="page-subnav" :aria-label="translate('runtimeSettings.navigation')">
      <RouterLink to="/settings/runtimes">{{ translate('runtimeSettings.title') }}</RouterLink>
      <RouterLink to="/settings/appearance">{{ translate('runtimeSettings.appearance') }}</RouterLink>
      <RouterLink to="/settings/diagnostics">{{ translate('diagnostics.title') }}</RouterLink>
    </nav>

    <GcAlert
      v-if="unavailable || runtime === null"
      level="error"
      :title="translate('runtimeSettings.statusUnavailable')"
    >
      {{ translate('runtimeSettings.metadataUnavailable') }}
    </GcAlert>

    <GcAlert
      v-else-if="bundled"
      level="info"
      :title="translate('runtimeSettings.protectedTitle')"
    >
      <p>{{ translate('runtimeSettings.protectedMessage') }}</p>
      <p>{{ translate('runtimeSettings.developmentSupport') }}</p>
      <GcBadge :status="runtime.runtimeLifecycle === 'ready' ? 'ready' : 'offline'">
        {{ runtime.runtimeLifecycle }}
      </GcBadge>
    </GcAlert>

    <GcAlert
      v-else
      level="info"
      :title="translate('runtimeSettings.externalTitle')"
    >
      <p>{{ translate('runtimeSettings.externalMessage') }}</p>
      <GcBadge :status="runtime.runtime === 'live' ? 'ready' : 'offline'">
        {{ runtime.runtime }}
      </GcBadge>
    </GcAlert>
  </section>
</template>
