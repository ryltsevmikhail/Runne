<script setup lang="ts">
import { Terminal } from 'lucide-vue-next'

import type { ProcessOutputChunk } from '@/entities/process'
import { translate } from '@/shared/i18n'

defineProps<{
  processId: string | null
  chunks: readonly ProcessOutputChunk[]
  loading: boolean
  error: boolean
}>()
</script>

<template>
  <section
    class="terminal-panel"
    aria-labelledby="terminal-title"
  >
    <div class="panel-heading">
      <Terminal
        :size="15"
        aria-hidden="true"
      />
      <h2 id="terminal-title">{{ translate('terminal.title') }}</h2>
    </div>
    <p
      v-if="loading"
      aria-live="polite"
    >
      {{ translate('terminal.loading') }}
    </p>
    <p
      v-else-if="error"
      role="alert"
    >
      {{ translate('terminal.unavailable') }}
    </p>
    <p v-else-if="processId === null">
      {{ translate('terminal.empty') }}
    </p>
    <pre
      v-else
      class="terminal-panel__output"
      aria-live="polite"
    ><span v-for="chunk in chunks" :key="`${chunk.stream}-${chunk.sequence}`">{{ chunk.text }}</span></pre>
  </section>
</template>
