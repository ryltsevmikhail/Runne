<script setup lang="ts">
import { Bot, CircleGauge, Command, Cpu, PanelTop } from 'lucide-vue-next'

import { translate } from '@/shared/i18n'
</script>

<template>
  <section
    class="conversation-capability-controls"
    data-capability="conversation-controls"
    :aria-label="translate('conversationControls.unavailable')"
  >
    <p
      id="conversation-controls-unavailable"
      class="conversation-capability-controls__description"
    >
      <strong>{{ translate('conversationControls.unavailable') }}</strong>
      {{ translate('conversationControls.unavailableDescription') }}
    </p>
    <div class="conversation-capability-controls__actions">
      <button
        type="button"
        disabled
        :aria-label="translate('conversationControls.command')"
        aria-describedby="conversation-controls-unavailable"
      >
        <Command
          :size="15"
          aria-hidden="true"
        />
        <span>{{ translate('conversationControls.command') }}</span>
      </button>
      <button
        type="button"
        disabled
        :aria-label="translate('conversationControls.context')"
        aria-describedby="conversation-controls-unavailable"
      >
        <PanelTop
          :size="15"
          aria-hidden="true"
        />
        <span>{{ translate('conversationControls.context') }}</span>
      </button>
      <button
        type="button"
        disabled
        :aria-label="translate('conversationControls.agent')"
        aria-describedby="conversation-controls-unavailable"
      >
        <Bot
          :size="15"
          aria-hidden="true"
        />
        <span>{{ translate('conversationControls.agent') }}</span>
      </button>
      <button
        type="button"
        disabled
        :aria-label="translate('conversationControls.model')"
        aria-describedby="conversation-controls-unavailable"
      >
        <Cpu
          :size="15"
          aria-hidden="true"
        />
        <span>{{ translate('conversationControls.model') }}</span>
      </button>
      <button
        type="button"
        disabled
        :aria-label="translate('conversationControls.budget')"
        aria-describedby="conversation-controls-unavailable"
      >
        <CircleGauge
          :size="15"
          aria-hidden="true"
        />
        <span>{{ translate('conversationControls.budget') }}</span>
      </button>
    </div>
  </section>
</template>
