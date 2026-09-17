<script setup lang="ts">
import { translate } from '@/shared/i18n'

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
    <div class="target-capability-boundary__content">
      <h2>{{ title }}</h2>
      <p>{{ description }}</p>
      <slot />
    </div>
    <details class="target-capability-boundary__details">
      <summary>{{ translate('targetCapability.identifier') }}</summary>
      <code>{{ capability }}</code>
    </details>
  </section>
</template>

<style scoped>
.target-capability-boundary {
  display: flex;
  align-items: start;
  justify-content: space-between;
  gap: var(--runne-space-md);
  padding: 10px 0;
  border-top: 1px solid var(--border);
  border-bottom: 1px solid var(--border);
}

.target-capability-boundary__content { min-width: 0; }

.target-capability-boundary h2 {
  margin: 0;
  color: var(--text);
  font-size: 13px;
  font-weight: 650;
}

.target-capability-boundary p {
  margin: 3px 0 0;
  color: var(--runne-text-secondary);
  font-size: 13px;
  line-height: 1.45;
}

.target-capability-boundary__details {
  flex: 0 0 auto;
  color: var(--text-muted);
  font-family: var(--runne-font-mono);
  font-size: 11px;
}

.target-capability-boundary__details summary { cursor: pointer; }
.target-capability-boundary__details summary:focus-visible { outline: 2px solid var(--runne-accent); outline-offset: 3px; }
.target-capability-boundary__details code { display: block; margin-top: 6px; }

@media (max-width: 540px) {
  .target-capability-boundary { align-items: stretch; flex-direction: column; }
}
</style>
