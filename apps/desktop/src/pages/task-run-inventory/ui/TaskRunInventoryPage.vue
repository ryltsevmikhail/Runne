<script setup lang="ts">
import { translate } from '@/shared/i18n'
import { TargetCapabilityBoundary } from '@/shared/ui/target-capability'
</script>

<template>
  <section class="task-run-inventory-page">
    <header class="task-run-inventory-page__header">
      <div>
        <h1>{{ translate('taskRunInventory.title') }}</h1>
        <p>{{ translate('taskRunInventory.subtitle') }}</p>
      </div>
    </header>

    <div class="task-run-inventory-page__content">
      <TargetCapabilityBoundary
        data-capability="task-run-inventory"
        :title="translate('targetCapability.unavailable')"
        :description="translate('targetCapability.unavailableDescription', { capability: 'task-run-inventory' })"
        capability="task-run-inventory"
      />
    </div>
  </section>
</template>
