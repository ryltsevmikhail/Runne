<template>
  <div class="workspace-frame workspace-panels">
    <aside
      class="workspace-frame__explorer workspace-panel workspace-panel--tree"
      aria-label="Project tree"
    >
      <slot name="explorer" />
    </aside>
    <main
      class="workspace-frame__conversation workspace-panel workspace-panel--main workspace-panel--chat"
      aria-label="Conversation"
    >
      <slot name="conversation" />
    </main>
    <aside
      class="workspace-frame__details workspace-panel workspace-panel--details"
      aria-label="Details"
    >
      <slot name="details" />
    </aside>
  </div>
</template>
