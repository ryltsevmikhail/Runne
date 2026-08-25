<script setup lang="ts">
import { GcAlert } from '@runne/product/shared/ui'
import { isTauri } from '@tauri-apps/api/core'
import { onMounted, ref } from 'vue'

import type { DiagnosticsSnapshot } from '@/shared/api/platform/diagnostics'
import { getDiagnostics } from '@/shared/api/platform/diagnostics'
import type {
  DiagnosticsExportPreview,
  DiagnosticsExportResult,
} from '@/shared/api/platform/diagnostics-export'
import {
  exportDiagnostics,
  getDiagnosticsExportPreview,
} from '@/shared/api/platform/diagnostics-export'
import type { OperationalTelemetrySnapshot } from '@/shared/api/platform/operational-telemetry'
import { getOperationalTelemetry } from '@/shared/api/platform/operational-telemetry'
import { translate } from '@/shared/i18n'

type LoadDiagnostics = () => Promise<DiagnosticsSnapshot>
type LoadOperationalTelemetry = () => Promise<OperationalTelemetrySnapshot>
type LoadExportPreview = () => Promise<DiagnosticsExportPreview>
type ExportReport = () => Promise<DiagnosticsExportResult>

const props = withDefaults(defineProps<{
  loadDiagnostics?: LoadDiagnostics
  loadOperationalTelemetry?: LoadOperationalTelemetry
  loadExportPreview?: LoadExportPreview
  exportReport?: ExportReport
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
  loadExportPreview: async (): Promise<DiagnosticsExportPreview> => {
    if (!isTauri()) throw new Error('native diagnostics export unavailable')
    return getDiagnosticsExportPreview()
  },
  exportReport: async (): Promise<DiagnosticsExportResult> => {
    if (!isTauri()) throw new Error('native diagnostics export unavailable')
    return exportDiagnostics()
  },
})

const diagnostics = ref<DiagnosticsSnapshot | null>(null)
const loading = ref(true)
const error = ref(false)
const telemetry = ref<OperationalTelemetrySnapshot | null>(null)
const telemetryLoading = ref(true)
const telemetryRefreshFailed = ref(false)
const exporting = ref(false)
const exportError = ref(false)
const exportStatus = ref<DiagnosticsExportResult['status'] | null>(null)

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

async function runExport(): Promise<void> {
  exporting.value = true
  exportError.value = false
  exportStatus.value = null
  try {
    const preview = await props.loadExportPreview()
    if (preview.estimatedBytes > 128 * 1024) throw new Error('diagnostics export too large')
    exportStatus.value = (await props.exportReport()).status
  }
  catch {
    exportError.value = true
  }
  finally {
    exporting.value = false
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
          {{ translate('diagnostics.title') }}
        </h1>
        <p>{{ translate('diagnostics.description') }}</p>
      </div>
      <button
        class="primary-button"
        type="button"
        :disabled="telemetryLoading"
        @click="refreshTelemetry"
      >
        {{ translate('diagnostics.refresh') }}
      </button>
      <button
        class="secondary-button"
        data-testid="export-diagnostics"
        type="button"
        :disabled="exporting"
        @click="runExport"
      >
        {{ exporting ? translate('diagnostics.prepareExport') : translate('diagnostics.export') }}
      </button>
    </header>

    <p
      v-if="exportStatus === 'saved'"
      class="status-message"
      role="status"
    >
      {{ translate('diagnostics.exportSaved') }}
    </p>
    <p
      v-else-if="exportStatus === 'cancelled'"
      class="status-message"
      role="status"
    >
      {{ translate('diagnostics.exportCancelled') }}
    </p>
    <GcAlert
      v-if="exportError"
      level="error"
      :title="translate('diagnostics.exportUnavailable')"
      role="alert"
    >
      {{ translate('diagnostics.exportUnavailableMessage') }}
    </GcAlert>

    <div
      v-if="loading"
      class="empty-state"
      aria-live="polite"
    >
      <h2>{{ translate('diagnostics.loading') }}</h2>
    </div>

    <GcAlert
      v-else-if="error || diagnostics === null"
      level="error"
      :title="translate('diagnostics.unavailable')"
      role="alert"
    >
      {{ translate('diagnostics.unavailableMessage') }}
    </GcAlert>

    <dl
      v-else
      class="diagnostics-grid"
    >
      <div>
        <dt>{{ translate('diagnostics.appVersion') }}</dt>
        <dd>{{ diagnostics.appVersion }}</dd>
      </div>
      <div>
        <dt>{{ translate('diagnostics.platform') }}</dt>
        <dd>{{ diagnostics.platform }}</dd>
      </div>
      <div>
        <dt>{{ translate('diagnostics.databaseSchema') }}</dt>
        <dd>{{ diagnostics.databaseSchemaVersion }}</dd>
      </div>
      <div>
        <dt>{{ translate('diagnostics.databaseGeneration') }}</dt>
        <dd>{{ diagnostics.databaseGeneration }}</dd>
      </div>
      <div>
        <dt>{{ translate('diagnostics.projectCount') }}</dt>
        <dd>{{ diagnostics.projectCount }}</dd>
      </div>
      <div>
        <dt>{{ translate('diagnostics.runtimeMode') }}</dt>
        <dd>{{ diagnostics.runtimeMode === 'external_local' ? translate('diagnostics.externalRuntime') : translate('diagnostics.bundledRuntime') }}</dd>
      </div>
      <div>
        <dt>{{ translate('diagnostics.runtimeConnection') }}</dt>
        <dd>{{ diagnostics.runtime }}</dd>
      </div>
      <div>
        <dt>{{ translate('diagnostics.runtimeLifecycle') }}</dt>
        <dd>{{ diagnostics.runtimeLifecycle }}</dd>
      </div>
      <div v-if="diagnostics.runtimeFailure !== null">
        <dt>{{ translate('diagnostics.actionableFailure') }}</dt>
        <dd>{{ diagnostics.runtimeFailure }}</dd>
      </div>
    </dl>

    <section
      v-if="!telemetryLoading"
      class="operational-telemetry"
      aria-labelledby="operational-telemetry-title"
    >
      <h2 id="operational-telemetry-title">
        {{ translate('diagnostics.telemetryTitle') }}
      </h2>
      <GcAlert
        v-if="telemetry === null"
        level="error"
        :title="translate('diagnostics.telemetryUnavailable')"
        role="alert"
      >
        {{ translate('diagnostics.telemetryUnavailableMessage') }}
      </GcAlert>
      <template v-else>
        <p
          v-if="telemetryRefreshFailed"
          role="status"
        >
          {{ translate('diagnostics.telemetryStale') }}
        </p>
        <dl class="diagnostics-grid operational-telemetry__grid">
          <div>
            <dt>{{ translate('diagnostics.runtimeTelemetry') }}</dt>
            <dd>{{ telemetry.runtime.snapshot === null ? translate('diagnostics.telemetryUnavailableValue') : translate('diagnostics.telemetryAvailableValue') }}</dd>
          </div>
          <div>
            <dt>{{ translate('diagnostics.freshnessCompleteness') }}</dt>
            <dd>{{ telemetry.runtime.meta.freshness }} / {{ telemetry.runtime.meta.completeness }}</dd>
          </div>
          <div>
            <dt>{{ translate('diagnostics.hostFreshnessCompleteness') }}</dt>
            <dd>{{ telemetry.hostLifecycle.meta.freshness }} / {{ telemetry.hostLifecycle.meta.completeness }}</dd>
          </div>
          <div>
            <dt>{{ translate('diagnostics.hostLifecycle') }}</dt>
            <dd>{{ telemetry.hostLifecycle.current?.lifecycle ?? 'unavailable' }}</dd>
          </div>
          <div>
            <dt>{{ translate('diagnostics.restartOrdinal') }}</dt>
            <dd>{{ telemetry.hostLifecycle.current?.restartOrdinal ?? 'unavailable' }}</dd>
          </div>
          <div>
            <dt>{{ translate('diagnostics.launchGeneration') }}</dt>
            <dd>{{ telemetry.hostLifecycle.current?.runtimeLaunchGeneration ?? 'unavailable' }}</dd>
          </div>
          <div>
            <dt>{{ translate('diagnostics.lifecycleEvents') }}</dt>
            <dd>{{ telemetry.hostLifecycle.events?.length ?? 'unavailable' }} ({{ telemetry.hostLifecycle.eventStatus }})</dd>
          </div>
          <div>
            <dt>{{ translate('diagnostics.droppedEvents') }}</dt>
            <dd>{{ telemetry.hostLifecycle.producerDroppedEventCount }} / {{ telemetry.hostLifecycle.evictedEventCount }}</dd>
          </div>
        </dl>
      </template>
    </section>
  </section>
</template>
