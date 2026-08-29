<script setup lang="ts">
import { GcAlert, GcBadge } from '@gocode/product/shared/ui'
import { isTauri } from '@tauri-apps/api/core'
import { Activity, CheckCircle2, Database, LockKeyhole, ServerCog } from 'lucide-vue-next'
import { computed, onMounted, ref } from 'vue'
import { RouterLink } from 'vue-router'

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
const modeLabel = computed(() => bundled.value ? 'Bundled runtime' : 'External runtime')
const connectionLabel = computed(() => runtime.value?.runtime.replaceAll('_', ' ') ?? 'Unavailable')
const lifecycleLabel = computed(() => runtime.value?.runtimeLifecycle.replaceAll('_', ' ') ?? 'Unavailable')

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
  <section class="runtime-settings-page" aria-labelledby="runtime-settings-title">
    <header class="page-header">
      <div>
        <p class="eyebrow">Settings</p>
        <h1 id="runtime-settings-title">Runtime</h1>
        <p>Inspect the protected execution environment and its current connection state.</p>
      </div>
      <RouterLink class="secondary-action" to="/diagnostics">
        <Activity :size="15" aria-hidden="true" />
        Open diagnostics
      </RouterLink>
    </header>

    <GcAlert
      v-if="unavailable || runtime === null"
      level="error"
      title="Runtime status unavailable"
    >
      Safe runtime metadata could not be read.
    </GcAlert>

    <template v-else>
      <div class="runtime-summary">
        <div class="runtime-summary__identity">
          <span class="runtime-mark"><ServerCog :size="21" aria-hidden="true" /></span>
          <div>
            <span>Execution environment</span>
            <strong>{{ modeLabel }}</strong>
          </div>
        </div>
        <GcBadge :status="runtime.runtimeLifecycle === 'ready' || runtime.runtime === 'live' ? 'ready' : 'offline'">
          {{ lifecycleLabel }}
        </GcBadge>
      </div>

      <dl class="runtime-facts">
        <div><dt>Mode</dt><dd>{{ modeLabel }}</dd></div>
        <div><dt>Connection</dt><dd>{{ connectionLabel }}</dd></div>
        <div><dt>Lifecycle</dt><dd>{{ lifecycleLabel }}</dd></div>
        <div><dt>Failure</dt><dd>{{ runtime.runtimeFailure?.replaceAll('_', ' ') ?? 'None reported' }}</dd></div>
      </dl>

      <div class="runtime-settings-grid">
        <GcAlert v-if="bundled" level="info" title="Protected bundled runtime">
          <p>Runne launches only the verified bundled daemon through protected one-time activation.</p>
          <p>The runtime mode is fixed for this desktop process and never changes after a connection failure.</p>
          <p>macOS support in this slice is development/ad-hoc only.</p>
        </GcAlert>
        <GcAlert v-else level="info" title="External runtime mode">
          <p>This mode was selected explicitly. Runne connects through the external profile but never stops or adopts that daemon.</p>
        </GcAlert>

        <section class="readiness-panel" aria-labelledby="readiness-title">
          <div class="settings-section-heading">
            <div>
              <span>Safety contract</span>
              <h2 id="readiness-title">Runtime readiness</h2>
            </div>
            <LockKeyhole :size="18" aria-hidden="true" />
          </div>
          <ul>
            <li><CheckCircle2 :size="15" aria-hidden="true" /> Native mode remains immutable during this process</li>
            <li><CheckCircle2 :size="15" aria-hidden="true" /> Project content is excluded from diagnostics</li>
            <li><Database :size="15" aria-hidden="true" /> Runtime metadata stays on this device</li>
          </ul>
        </section>
      </div>
    </template>
  </section>
</template>
