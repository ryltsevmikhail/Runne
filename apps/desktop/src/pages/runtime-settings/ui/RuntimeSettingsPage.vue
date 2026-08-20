<script setup lang="ts">
import { GcAlert, GcBadge } from '@runne/product/shared/ui'
import { isTauri } from '@tauri-apps/api/core'
import { computed, onMounted, ref } from 'vue'

import type { BootstrapState } from '@/shared/api/platform/bootstrap'
import { loadBootstrap } from '@/shared/api/platform/bootstrap'

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
          Runtime
        </h1>
        <p>The selected native mode is fixed for this desktop process. Connection failures never change it.</p>
      </div>
    </header>

    <GcAlert
      v-if="unavailable || runtime === null"
      level="error"
      title="Runtime status unavailable"
    >
      Safe runtime metadata could not be read.
    </GcAlert>

    <GcAlert
      v-else-if="bundled"
      level="info"
      title="Protected bundled runtime"
    >
      <p>Desktop launches only the verified bundled daemon through protected one-time activation.</p>
      <p>macOS support in this slice is development/ad-hoc only.</p>
      <GcBadge :status="runtime.runtimeLifecycle === 'ready' ? 'ready' : 'offline'">
        {{ runtime.runtimeLifecycle }}
      </GcBadge>
    </GcAlert>

    <GcAlert
      v-else
      level="info"
      title="External runtime mode"
    >
      <p>This mode was selected explicitly. Desktop connects through the external profile but never stops or adopts that daemon.</p>
      <GcBadge :status="runtime.runtime === 'live' ? 'ready' : 'offline'">
        {{ runtime.runtime }}
      </GcBadge>
    </GcAlert>
  </section>
</template>
