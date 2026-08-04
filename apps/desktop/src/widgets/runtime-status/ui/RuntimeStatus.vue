<script setup lang="ts">
import { computed } from 'vue'

import type {
  RuntimeConnectionState,
  RuntimeFailureCode,
  RuntimeLifecycleStatus,
  RuntimeMode,
} from '@/shared/api/platform/bootstrap'

const props = defineProps<{
  mode: RuntimeMode
  connection: RuntimeConnectionState
  lifecycle: RuntimeLifecycleStatus
  failure: RuntimeFailureCode | null
}>()

const failureLabels: Record<RuntimeFailureCode, string> = {
  configuration_required: 'Provider configuration is required',
  protected_activation_unavailable: 'Protected activation unavailable',
  bundled_executable_unavailable: 'Bundled runtime is missing',
  bundled_executable_identity_mismatch: 'Executable verification failed',
  protected_readiness_rejected: 'Runtime verification failed',
  bundled_restart_exhausted: 'Restart limit reached',
  bundled_shutdown_incomplete: 'Shutdown could not be confirmed',
  unsupported_platform_backend: 'Protected activation is unsupported',
  downgraded_external_profile: 'Unsafe transport was rejected',
}

const lifecycleTitles: Record<RuntimeLifecycleStatus, string> = {
  configuration_required: 'Provider configuration required',
  starting: 'Runtime starting',
  ready: 'Runtime ready',
  restarting: 'Runtime restarting',
  degraded: 'Runtime degraded',
  failed: 'Runtime failed',
  external: 'External runtime',
}

const title = computed(() => lifecycleTitles[props.lifecycle])

const detail = computed(() => {
  if (props.failure !== null) {
    return failureLabels[props.failure]
  }
  switch (props.lifecycle) {
    case 'configuration_required':
      return 'Configure a provider to start the bundled runtime'
    case 'starting':
      return 'Protected activation'
    case 'ready':
      return props.connection === 'resync_required' ? 'Replay resync required' : 'Protected session'
    case 'restarting':
      return 'Rotating runtime session'
    case 'degraded':
      return props.connection === 'resync_required' ? 'Replay resync required' : 'Retrying safely'
    case 'failed':
      return 'Open diagnostics for details'
    case 'external':
      return props.connection === 'live' ? 'Explicit mode · connected' : `Explicit mode · ${props.connection}`
  }
  return 'Runtime unavailable'
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
