<script setup lang="ts">
import { GcAlert } from '@gocode/product/shared/ui'
import { isTauri } from '@tauri-apps/api/core'
import { onMounted, ref } from 'vue'

import type { DiagnosticsSnapshot } from '@/shared/api/platform/diagnostics'
import { getDiagnostics } from '@/shared/api/platform/diagnostics'

type LoadDiagnostics = () => Promise<DiagnosticsSnapshot>

const props = withDefaults(defineProps<{
  loadDiagnostics?: LoadDiagnostics
}>(), {
  loadDiagnostics: async (): Promise<DiagnosticsSnapshot> => isTauri()
    ? getDiagnostics()
    : {
        appVersion: 'development',
        platform: 'browser',
        databaseSchemaVersion: 3,
        databaseGeneration: 1,
        projectCount: 0,
        runtime: 'unconfigured',
      },
})

const diagnostics = ref<DiagnosticsSnapshot | null>(null)
const loading = ref(true)
const error = ref(false)

onMounted(async () => {
  try {
    diagnostics.value = await props.loadDiagnostics()
  }
  catch {
    error.value = true
  }
  finally {
    loading.value = false
  }
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
        <dt>Runtime</dt>
        <dd>{{ diagnostics.runtime }}</dd>
      </div>
    </dl>
  </section>
</template>
