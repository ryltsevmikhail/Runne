<script setup lang="ts">
import { computed } from 'vue'

import type { DiagnosticsSnapshot as DiagnosticsSnapshotDto } from '@/shared/api/platform/diagnostics'
import { translate } from '@/shared/i18n'

const props = defineProps<{
  readonly snapshot: DiagnosticsSnapshotDto
}>()

const runtimeMode = computed(() => props.snapshot.runtimeMode === 'external_local'
  ? translate('diagnostics.externalRuntime')
  : translate('diagnostics.bundledRuntime'))
</script>

<template>
  <section
    class="diagnostics-snapshot"
    :aria-label="translate('diagnostics.currentRuntimeSnapshot')"
  >
    <p class="system-surface__notice">
      {{ translate('diagnostics.redactedSnapshotNotice') }}
    </p>

    <div class="diagnostics-snapshot__groups">
      <dl class="system-fact-grid">
        <div><dt>{{ translate('diagnostics.appVersion') }}</dt><dd>{{ snapshot.appVersion }}</dd></div>
        <div><dt>{{ translate('diagnostics.platform') }}</dt><dd>{{ snapshot.platform }}</dd></div>
        <div><dt>{{ translate('diagnostics.databaseSchema') }}</dt><dd>{{ snapshot.databaseSchemaVersion }}</dd></div>
        <div><dt>{{ translate('diagnostics.databaseGeneration') }}</dt><dd>{{ snapshot.databaseGeneration }}</dd></div>
        <div><dt>{{ translate('diagnostics.projectCount') }}</dt><dd>{{ snapshot.projectCount }}</dd></div>
      </dl>
      <dl
        class="system-fact-grid"
        data-testid="diagnostics-runtime-fields"
      >
        <div><dt>{{ translate('diagnostics.runtimeMode') }}</dt><dd>{{ runtimeMode }}</dd></div>
        <div><dt>{{ translate('diagnostics.runtimeConnection') }}</dt><dd>{{ snapshot.runtime }}</dd></div>
        <div><dt>{{ translate('diagnostics.runtimeLifecycle') }}</dt><dd>{{ snapshot.runtimeLifecycle }}</dd></div>
        <div><dt>{{ translate('diagnostics.actionableFailure') }}</dt><dd>{{ snapshot.runtimeFailure ?? translate('diagnostics.none') }}</dd></div>
      </dl>
    </div>

    <aside class="system-surface__boundary">
      <strong>{{ translate('diagnostics.implementedDtoBoundary') }}</strong>
      <p>{{ translate('diagnostics.dtoBoundaryMessage') }}</p>
    </aside>
  </section>
</template>
