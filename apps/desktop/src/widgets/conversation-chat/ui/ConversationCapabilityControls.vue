<script setup lang="ts">
import { translate } from '@/shared/i18n'
</script>

<template>
  <details
    class="conversation-capability-controls"
    data-capability="conversation-controls"
  >
    <summary>{{ translate('conversationControls.unavailable') }}</summary>
    <p class="conversation-capability-controls__description">
      {{ translate('conversationControls.unavailableDescription') }}
    </p>
  </details>
</template>
