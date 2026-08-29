<script setup lang="ts">
import { Filter, RefreshCw, Search } from 'lucide-vue-next'
import { computed } from 'vue'

import { translate } from '@/shared/i18n'
import { TargetCapabilityBoundary } from '@/shared/ui/target-capability'

const summaryLabels = computed(() => [
  translate('taskRunInventory.running'),
  translate('taskRunInventory.waitingApproval'),
  translate('taskRunInventory.completedToday'),
  translate('taskRunInventory.failed'),
])
</script>

<template>
  <section class="task-run-inventory-page">
    <header class="task-run-inventory-page__header">
      <div>
        <h1>{{ translate('taskRunInventory.title') }}</h1>
        <p>{{ translate('taskRunInventory.subtitle') }}</p>
      </div>
      <div class="task-run-inventory-page__header-actions">
        <button
          type="button"
          disabled
          data-inventory-control
          :aria-label="translate('taskRunInventory.refresh')"
        >
          <RefreshCw
            :size="18"
            aria-hidden="true"
          />
        </button>
        <button
          type="button"
          disabled
          data-inventory-control
          :aria-label="translate('taskRunInventory.filter')"
        >
          <Filter
            :size="18"
            aria-hidden="true"
          />
        </button>
      </div>
    </header>

    <div class="task-run-inventory-page__content">
      <TargetCapabilityBoundary
        data-capability="task-run-inventory"
        :title="translate('targetCapability.unavailable')"
        :description="translate('targetCapability.unavailableDescription', { capability: 'task-run-inventory' })"
        capability="task-run-inventory"
      />
      <div
        class="task-run-inventory-page__summary"
        :aria-label="translate('taskRunInventory.summary')"
      >
        <div
          v-for="label in summaryLabels"
          :key="label"
          class="task-run-inventory-page__summary-card"
        >
          <span>{{ label }}</span>
          <strong data-summary-value>{{ translate('taskRunInventory.unavailable') }}</strong>
        </div>
      </div>

      <div class="task-run-inventory-page__toolbar">
        <label class="task-run-inventory-page__search">
          <Search
            :size="16"
            aria-hidden="true"
          />
          <input
            type="search"
            disabled
            data-inventory-control
            :aria-label="translate('taskRunInventory.search')"
            :placeholder="translate('taskRunInventory.searchPlaceholder')"
          >
        </label>
        <div
          class="task-run-inventory-page__filters"
          :aria-label="translate('taskRunInventory.statusFilters')"
        >
          <button
            v-for="label in [
              translate('taskRunInventory.all'),
              translate('taskRunInventory.active'),
              translate('taskRunInventory.completed'),
            ]"
            :key="label"
            type="button"
            disabled
            data-inventory-control
          >
            {{ label }}
          </button>
        </div>
      </div>

      <div class="task-run-inventory-page__table-shell">
        <table class="task-run-inventory-page__table">
          <thead>
            <tr>
              <th>{{ translate('taskRunInventory.runTask') }}</th>
              <th>{{ translate('taskRunInventory.project') }}</th>
              <th>{{ translate('taskRunInventory.agent') }}</th>
              <th>{{ translate('taskRunInventory.status') }}</th>
              <th>{{ translate('taskRunInventory.updated') }}</th>
            </tr>
          </thead>
          <tbody />
        </table>
        <p
          data-inventory-table-state
          role="status"
        >
          {{ translate('taskRunInventory.tableUnavailable') }}
        </p>
      </div>
    </div>
  </section>
</template>
