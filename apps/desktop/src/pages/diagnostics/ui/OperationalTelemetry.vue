<script setup lang="ts">
import { GcAlert } from '@runne/product/shared/ui'

import type { OperationalTelemetrySnapshot } from '@/shared/api/platform/operational-telemetry'
import { translate } from '@/shared/i18n'

defineProps<{
  readonly refreshFailed: boolean
  readonly telemetry: OperationalTelemetrySnapshot | null
}>()
</script>

<template>
  <section
    class="operational-telemetry"
    aria-labelledby="operational-telemetry-title"
  >
    <header class="system-surface__section-heading">
      <div>
        <p class="system-surface__eyebrow">
          {{ translate('diagnostics.observedTelemetry') }}
        </p>
        <h2 id="operational-telemetry-title">
          {{ translate('diagnostics.telemetryTitle') }}
        </h2>
      </div>
    </header>

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
        v-if="refreshFailed"
        class="system-surface__stale"
        role="status"
      >
        {{ translate('diagnostics.telemetryStale') }}
      </p>
      <dl class="system-fact-grid operational-telemetry__grid">
        <div><dt>{{ translate('diagnostics.runtimeTelemetry') }}</dt><dd>{{ telemetry.runtime.snapshot === null ? translate('diagnostics.telemetryUnavailableValue') : translate('diagnostics.telemetryAvailableValue') }}</dd></div>
        <div><dt>{{ translate('diagnostics.freshnessCompleteness') }}</dt><dd>{{ telemetry.runtime.meta.freshness }} / {{ telemetry.runtime.meta.completeness }}</dd></div>
        <div><dt>{{ translate('diagnostics.hostFreshnessCompleteness') }}</dt><dd>{{ telemetry.hostLifecycle.meta.freshness }} / {{ telemetry.hostLifecycle.meta.completeness }}</dd></div>
        <div><dt>{{ translate('diagnostics.hostLifecycle') }}</dt><dd>{{ telemetry.hostLifecycle.current?.lifecycle ?? translate('diagnostics.unavailableValue') }}</dd></div>
        <div><dt>{{ translate('diagnostics.restartOrdinal') }}</dt><dd>{{ telemetry.hostLifecycle.current?.restartOrdinal ?? translate('diagnostics.unavailableValue') }}</dd></div>
        <div><dt>{{ translate('diagnostics.launchGeneration') }}</dt><dd>{{ telemetry.hostLifecycle.current?.runtimeLaunchGeneration ?? translate('diagnostics.unavailableValue') }}</dd></div>
        <div><dt>{{ translate('diagnostics.lifecycleEvents') }}</dt><dd>{{ telemetry.hostLifecycle.events?.length ?? translate('diagnostics.unavailableValue') }} ({{ telemetry.hostLifecycle.eventStatus }})</dd></div>
        <div><dt>{{ translate('diagnostics.droppedEvents') }}</dt><dd>{{ telemetry.hostLifecycle.producerDroppedEventCount }} / {{ telemetry.hostLifecycle.evictedEventCount }}</dd></div>
      </dl>
    </template>
  </section>
</template>
