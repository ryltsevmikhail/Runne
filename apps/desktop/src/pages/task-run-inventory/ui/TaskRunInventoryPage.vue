<script setup lang="ts">
import { Filter, RefreshCw, Search } from 'lucide-vue-next'

import { translate } from '@/shared/i18n'
import { TargetCapabilityBoundary } from '@/shared/ui/target-capability'

const summaryLabels = ['Running', 'Waiting approval', 'Completed today', 'Failed']
</script>

<template>
  <section class="task-run-inventory-page">
    <header class="task-run-inventory-page__header">
      <div>
        <h1>Task runs</h1>
        <p>Execution history across projects and agents</p>
      </div>
      <div class="task-run-inventory-page__header-actions">
        <button
          type="button"
          disabled
          data-inventory-control
          aria-label="Refresh task runs"
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
          aria-label="Filter task runs"
        >
          <Filter
            :size="18"
            aria-hidden="true"
          />
        </button>
      </div>
    </header>

    <div class="task-run-inventory-page__content">
      <div
        class="task-run-inventory-page__summary"
        aria-label="Task run summary"
      >
        <div
          v-for="label in summaryLabels"
          :key="label"
          class="task-run-inventory-page__summary-card"
        >
          <span>{{ label }}</span>
          <strong data-summary-value>Unavailable</strong>
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
            aria-label="Search task runs"
            placeholder="Search run, project, or agent"
          >
        </label>
        <div
          class="task-run-inventory-page__filters"
          aria-label="Task run status filters"
        >
          <button
            v-for="label in ['All', 'Active', 'Completed']"
            :key="label"
            type="button"
            disabled
            data-inventory-control
          >
            {{ label }}
          </button>
        </div>
      </div>

      <table class="task-run-inventory-page__table">
        <thead>
          <tr><th>Run / task</th><th>Project</th><th>Agent</th><th>Status</th><th>Updated</th></tr>
        </thead>
        <tbody />
        <tfoot>
          <tr>
            <td colspan="5">
              <TargetCapabilityBoundary
                data-capability="task-run-inventory"
                :title="translate('targetCapability.unavailable')"
                :description="translate('targetCapability.unavailableDescription', { capability: 'task-run-inventory' })"
                capability="task-run-inventory"
              />
            </td>
          </tr>
        </tfoot>
      </table>
    </div>
  </section>
</template>
