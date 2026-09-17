<script setup lang="ts">
import { PanelLeft, PanelRight } from 'lucide-vue-next'
import { ref } from 'vue'

import { translate } from '@/shared/i18n'

const explorerOpen = ref(false)
const detailsOpen = ref(false)
</script>

<template>
  <div class="workspace-frame">
    <div class="workspace-frame__toolbar">
      <button
        type="button"
        class="workspace-frame__toggle"
        :aria-label="translate(explorerOpen ? 'workspace.hideProjectTree' : 'workspace.showProjectTree')"
        aria-controls="workspace-explorer"
        :aria-pressed="explorerOpen"
        @click="explorerOpen = !explorerOpen"
      >
        <PanelLeft
          :size="15"
          aria-hidden="true"
        />
        <span>{{ translate(explorerOpen ? 'workspace.hideProjectTree' : 'workspace.showProjectTree') }}</span>
      </button>
      <button
        type="button"
        class="workspace-frame__toggle"
        :aria-label="translate(detailsOpen ? 'workspace.hideDetails' : 'workspace.showDetails')"
        aria-controls="workspace-details"
        :aria-pressed="detailsOpen"
        @click="detailsOpen = !detailsOpen"
      >
        <PanelRight
          :size="15"
          aria-hidden="true"
        />
        <span>{{ translate(detailsOpen ? 'workspace.hideDetails' : 'workspace.showDetails') }}</span>
      </button>
    </div>
    <div
      class="workspace-frame__content"
      :data-explorer-open="explorerOpen"
      :data-details-open="detailsOpen"
    >
      <aside
        v-show="explorerOpen"
        id="workspace-explorer"
        class="workspace-frame__explorer workspace-panel workspace-panel--tree"
        :aria-label="translate('workspace.projectTree')"
      >
        <slot name="explorer" />
      </aside>
      <section
        class="workspace-frame__conversation workspace-panel workspace-panel--main workspace-panel--chat"
        :aria-label="translate('conversation.kicker')"
      >
        <slot name="conversation" />
      </section>
      <aside
        v-show="detailsOpen"
        id="workspace-details"
        class="workspace-frame__details workspace-panel workspace-panel--details"
        :aria-label="translate('workspace.details')"
      >
        <slot name="details" />
      </aside>
    </div>
  </div>
</template>
