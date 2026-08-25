<script setup lang="ts">
import { computed } from 'vue'

import type {
  RuntimeConnectionState,
  RuntimeFailureCode,
  RuntimeLifecycleStatus,
  RuntimeMode,
} from '@/shared/api/platform/bootstrap'
import { translate, type LocaleKey } from '@/shared/i18n'

const props = defineProps<{
  mode: RuntimeMode
  connection: RuntimeConnectionState
  lifecycle: RuntimeLifecycleStatus
  failure: RuntimeFailureCode | null
}>()

const failureLabels: Record<RuntimeFailureCode, LocaleKey> = {
  configuration_required: 'runtime.failure.configuration',
  protected_activation_unavailable: 'runtime.failure.protectedActivation',
  bundled_executable_unavailable: 'runtime.failure.executableMissing',
  bundled_executable_identity_mismatch: 'runtime.failure.executableMismatch',
  protected_readiness_rejected: 'runtime.failure.readinessRejected',
  bundled_restart_exhausted: 'runtime.failure.restartExhausted',
  bundled_shutdown_incomplete: 'runtime.failure.shutdownIncomplete',
  unsupported_platform_backend: 'runtime.failure.unsupportedBackend',
  downgraded_external_profile: 'runtime.failure.unsafeTransport',
}

const lifecycleTitles: Record<RuntimeLifecycleStatus, LocaleKey> = {
  configuration_required: 'runtime.title.configuration',
  starting: 'runtime.title.starting',
  ready: 'runtime.title.ready',
  restarting: 'runtime.title.restarting',
  degraded: 'runtime.title.degraded',
  failed: 'runtime.title.failed',
  external: 'runtime.title.external',
}

const title = computed(() => translate(lifecycleTitles[props.lifecycle]))

const detail = computed(() => {
  if (props.failure !== null) {
    return translate(failureLabels[props.failure])
  }
  switch (props.lifecycle) {
    case 'configuration_required':
      return translate('runtime.detail.configureProvider')
    case 'starting':
      return translate('runtime.detail.protectedActivation')
    case 'ready':
      return props.connection === 'resync_required' ? translate('runtime.detail.replayResync') : translate('runtime.detail.protectedSession')
    case 'restarting':
      return translate('runtime.detail.rotatingSession')
    case 'degraded':
      return props.connection === 'resync_required' ? translate('runtime.detail.replayResync') : translate('runtime.detail.retryingSafely')
    case 'failed':
      return translate('runtime.detail.openDiagnostics')
    case 'external':
      return props.connection === 'live' ? translate('runtime.detail.externalConnected') : translate('runtime.detail.externalConnection', { connection: props.connection })
  }
  return translate('runtime.detail.unavailable')
})
</script>

<template>
  <div
    class="runtime-status"
    :data-lifecycle="lifecycle"
    :data-mode="mode"
    :data-connection="connection"
    :title="`${title}: ${detail}`"
    role="status"
    aria-live="polite"
  >
    <span
      class="status-dot"
      aria-hidden="true"
    />
    <span class="status-copy">
      <strong>{{ title }}</strong>
      <small>{{ detail }}</small>
    </span>
  </div>
</template>
