<script setup lang="ts">
import { translate } from '@/shared/i18n'
</script>

<template>
  <div class="workspace-frame workspace-panels">
    <aside
      class="workspace-frame__explorer workspace-panel workspace-panel--tree"
      :aria-label="translate('workspace.projectTree')"
    >
      <slot name="explorer" />
    </aside>
    <main
      class="workspace-frame__conversation workspace-panel workspace-panel--main workspace-panel--chat"
      :aria-label="translate('conversation.kicker')"
    >
      <slot name="conversation" />
    </main>
    <aside
      class="workspace-frame__details workspace-panel workspace-panel--details"
      :aria-label="translate('workspace.details')"
    >
      <slot name="details" />
    </aside>
  </div>
</template>
