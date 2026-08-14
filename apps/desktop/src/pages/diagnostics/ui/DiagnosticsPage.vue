<script setup lang="ts">
import { GcAlert } from '@gocode/product/shared/ui'
import { isTauri } from '@tauri-apps/api/core'
import { onMounted, ref } from 'vue'

import type { DiagnosticsSnapshot } from '@/shared/api/platform/diagnostics'
import { getDiagnostics } from '@/shared/api/platform/diagnostics'
import type { OperationalTelemetrySnapshot } from '@/shared/api/platform/operational-telemetry'
import { getOperationalTelemetry } from '@/shared/api/platform/operational-telemetry'

type LoadDiagnostics = () => Promise<DiagnosticsSnapshot>
type LoadOperationalTelemetry = () => Promise<OperationalTelemetrySnapshot>

const props = withDefaults(defineProps<{
  loadDiagnostics?: LoadDiagnostics
  loadOperationalTelemetry?: LoadOperationalTelemetry
}>(), {
  loadDiagnostics: async (): Promise<DiagnosticsSnapshot> => isTauri()
    ? getDiagnostics()
    : {
        appVersion: 'development',
        platform: 'browser',
        databaseSchemaVersion: 3,
        databaseGeneration: 1,
        projectCount: 0,
        runtimeMode: 'external_local',
        runtime: 'unconfigured',
        runtimeLifecycle: 'external',
        runtimeFailure: null,
      },
  loadOperationalTelemetry: async (): Promise<OperationalTelemetrySnapshot> => {
    if (!isTauri()) throw new Error('native telemetry unavailable')
    return getOperationalTelemetry()
  },
})

const diagnostics = ref<DiagnosticsSnapshot | null>(null)
const loading = ref(true)
const error = ref(false)
const telemetry = ref<OperationalTelemetrySnapshot | null>(null)
const telemetryLoading = ref(true)
const telemetryRefreshFailed = ref(false)

async function loadDiagnosticsData(): Promise<void> {
  try {
    diagnostics.value = await props.loadDiagnostics()
  }
  catch {
    error.value = true
  }
  finally {
    loading.value = false
  }
}

async function refreshTelemetry(): Promise<void> {
  telemetryLoading.value = true
  try {
    telemetry.value = await props.loadOperationalTelemetry()
    telemetryRefreshFailed.value = false
  }
  catch {
    telemetryRefreshFailed.value = telemetry.value !== null
  }
  finally {
    telemetryLoading.value = false
  }
}

onMounted(() => {
  void loadDiagnosticsData()
  void refreshTelemetry()
})
</script>

<template>
  <section aria-labelledby="diagnostics-title">
    <header class="page-header">
      <div>
        <h1 id="diagnostics-title">
          Diagnostics
        </h1>
        <p>Redacted local operational state. Paths and content are excluded.</p>
      </div>
      <button
        class="primary-button"
        type="button"
        :disabled="telemetryLoading"
        @click="refreshTelemetry"
      >
        Refresh
      </button>
    </header>

    <div
      v-if="loading"
      class="empty-state"
      aria-live="polite"
    >
      <h2>Loading diagnostics</h2>
    </div>

    <GcAlert
      v-else-if="error || diagnostics === null"
      level="error"
      title="Diagnostics unavailable"
      role="alert"
    >
      Safe local metadata could not be read.
    </GcAlert>

    <dl
      v-else
      class="diagnostics-grid"
    >
      <div>
        <dt>App version</dt>
        <dd>{{ diagnostics.appVersion }}</dd>
      </div>
      <div>
        <dt>Platform</dt>
        <dd>{{ diagnostics.platform }}</dd>
      </div>
      <div>
        <dt>Database schema</dt>
        <dd>{{ diagnostics.databaseSchemaVersion }}</dd>
      </div>
      <div>
        <dt>Database generation</dt>
        <dd>{{ diagnostics.databaseGeneration }}</dd>
      </div>
      <div>
        <dt>Local project count</dt>
        <dd>{{ diagnostics.projectCount }}</dd>
      </div>
      <div>
        <dt>Runtime mode</dt>
        <dd>{{ diagnostics.runtimeMode === 'external_local' ? 'External runtime' : 'Bundled runtime' }}</dd>
      </div>
      <div>
        <dt>Runtime connection</dt>
        <dd>{{ diagnostics.runtime }}</dd>
      </div>
      <div>
        <dt>Runtime lifecycle</dt>
        <dd>{{ diagnostics.runtimeLifecycle }}</dd>
      </div>
      <div v-if="diagnostics.runtimeFailure !== null">
        <dt>Actionable failure</dt>
        <dd>{{ diagnostics.runtimeFailure }}</dd>
      </div>
    </dl>

    <section
      v-if="!telemetryLoading"
      class="operational-telemetry"
      aria-labelledby="operational-telemetry-title"
    >
      <h2 id="operational-telemetry-title">
        Operational telemetry
      </h2>
      <GcAlert
        v-if="telemetry === null"
        level="error"
        title="Operational telemetry unavailable"
        role="alert"
      >
        Safe runtime and host lifecycle telemetry could not be read.
      </GcAlert>
      <template v-else>
        <p
          v-if="telemetryRefreshFailed"
          role="status"
        >
          Telemetry may be stale because the latest refresh failed.
        </p>
        <dl class="diagnostics-grid operational-telemetry__grid">
          <div>
            <dt>Runtime telemetry</dt>
            <dd>{{ telemetry.runtime.snapshot === null ? 'Runtime telemetry unavailable' : 'Runtime telemetry available' }}</dd>
          </div>
          <div>
            <dt>Runtime freshness / completeness</dt>
            <dd>{{ telemetry.runtime.meta.freshness }} / {{ telemetry.runtime.meta.completeness }}</dd>
          </div>
          <div>
            <dt>Host freshness / completeness</dt>
            <dd>{{ telemetry.hostLifecycle.meta.freshness }} / {{ telemetry.hostLifecycle.meta.completeness }}</dd>
          </div>
          <div>
            <dt>Host lifecycle</dt>
            <dd>{{ telemetry.hostLifecycle.current?.lifecycle ?? 'unavailable' }}</dd>
          </div>
          <div>
            <dt>Restart ordinal</dt>
            <dd>{{ telemetry.hostLifecycle.current?.restartOrdinal ?? 'unavailable' }}</dd>
          </div>
          <div>
            <dt>Launch generation</dt>
            <dd>{{ telemetry.hostLifecycle.current?.runtimeLaunchGeneration ?? 'unavailable' }}</dd>
          </div>
          <div>
            <dt>Lifecycle events</dt>
            <dd>{{ telemetry.hostLifecycle.events?.length ?? 'unavailable' }} ({{ telemetry.hostLifecycle.eventStatus }})</dd>
          </div>
          <div>
            <dt>Dropped / evicted events</dt>
            <dd>{{ telemetry.hostLifecycle.producerDroppedEventCount }} / {{ telemetry.hostLifecycle.evictedEventCount }}</dd>
          </div>
        </dl>
      </template>
    </section>
  </section>
</template>
