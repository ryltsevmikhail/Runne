<script setup lang="ts">
import { Activity, CheckCircle2, Clock3, ListChecks, Plus, Search, XCircle } from 'lucide-vue-next'
import { ref } from 'vue'
import { RouterLink } from 'vue-router'

const query = ref('')
const status = ref<'all' | 'running' | 'completed' | 'failed'>('all')

const filters = [
  { id: 'all', label: 'All' },
  { id: 'running', label: 'Running' },
  { id: 'completed', label: 'Completed' },
  { id: 'failed', label: 'Failed' },
] as const
</script>

<template>
  <section class="task-runs-page" aria-labelledby="task-runs-title">
    <header class="page-header">
      <div>
        <p class="eyebrow">Execution history</p>
        <h1 id="task-runs-title">Task runs</h1>
        <p>Review activity, progress, and outcomes across local projects.</p>
      </div>
      <RouterLink class="primary-button" to="/">
        <Plus :size="16" aria-hidden="true" />
        Open project
      </RouterLink>
    </header>

    <dl class="run-metrics" aria-label="Task run summary">
      <div>
        <dt><Activity :size="15" aria-hidden="true" /> Active</dt>
        <dd>0</dd>
      </div>
      <div>
        <dt><Clock3 :size="15" aria-hidden="true" /> Queued</dt>
        <dd>0</dd>
      </div>
      <div>
        <dt><CheckCircle2 :size="15" aria-hidden="true" /> Completed</dt>
        <dd>0</dd>
      </div>
      <div>
        <dt><XCircle :size="15" aria-hidden="true" /> Failed</dt>
        <dd>0</dd>
      </div>
    </dl>

    <div class="run-toolbar">
      <label class="run-search">
        <Search :size="15" aria-hidden="true" />
        <span class="sr-only">Search task runs</span>
        <input v-model="query" type="search" placeholder="Search by task or project" />
      </label>
      <div class="run-filters" aria-label="Filter task runs">
        <button
          v-for="filter in filters"
          :key="filter.id"
          type="button"
          :class="{ 'is-active': status === filter.id }"
          :aria-pressed="status === filter.id"
          @click="status = filter.id"
        >
          {{ filter.label }}
        </button>
      </div>
    </div>

    <div class="run-table-shell">
      <table class="run-table">
        <thead>
          <tr>
            <th>Task</th>
            <th>Project</th>
            <th>Agent</th>
            <th>Status</th>
            <th>Started</th>
          </tr>
        </thead>
      </table>
      <div class="run-empty" aria-live="polite">
        <span class="empty-icon"><ListChecks :size="24" aria-hidden="true" /></span>
        <h2>No task runs yet</h2>
        <p v-if="query || status !== 'all'">No runs match the current search and status filter.</p>
        <p v-else>Runs will appear here when an agent starts executing work in a project.</p>
        <RouterLink to="/">Choose a project</RouterLink>
      </div>
    </div>
  </section>
</template>
