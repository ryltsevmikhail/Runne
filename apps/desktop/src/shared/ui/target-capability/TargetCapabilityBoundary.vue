<script setup lang="ts">
import { GcAlert } from '@runne/product/shared/ui'

defineProps<{
  title: string
  description: string
  capability: string
}>()
</script>

<template>
  <section
    class="target-capability-boundary"
    role="status"
  >
    <GcAlert
      level="warning"
      :title="title"
    >
      <p>{{ description }}</p>
      <code class="target-capability-boundary__identifier">{{ capability }}</code>
      <slot />
    </GcAlert>
  </section>
</template>

<style scoped>
.target-capability-boundary__identifier {
  color: var(--runne-text-secondary);
}
</style>
