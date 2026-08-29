<script setup lang="ts">
defineOptions({ inheritAttrs: false })

export interface ProjectCard {
  name: string
  path: string
  slug: string
  status?: 'ready' | 'stale' | 'recovery'
  modifiedAt: string
}

defineProps<{
  project: ProjectCard
}>()

defineEmits<{
  click: []
}>()
</script>

<template>
  <article
    :class="['gc-project-card', project.status && `gc-project-card--${project.status}`]"
  >
    <button
      v-bind="$attrs"
      class="gc-project-card-main"
      type="button"
      @click="$emit('click')"
    >
      <span
        v-if="$slots.leading"
        class="gc-project-card-icon"
      >
        <slot name="leading" />
      </span>
      <span class="gc-project-card-copy">
        <span class="gc-project-card-header">
          <span class="gc-project-card-name">{{ project.name }}</span>
          <span
            v-if="project.status"
            :class="['gc-project-card-status', `gc-project-card-status--${project.status}`]"
          >
            {{ project.status === 'ready' ? 'Ready' : project.status === 'stale' ? 'Attention' : 'Recovery' }}
          </span>
        </span>
        <span class="gc-project-card-path">{{ project.path }}</span>
        <time class="gc-project-card-time">{{ project.modifiedAt }}</time>
      </span>
      <span
        v-if="$slots.trailing"
        class="gc-project-card-arrow"
      >
        <slot name="trailing" />
      </span>
    </button>
    <div
      v-if="$slots.actions"
      class="gc-project-card-actions"
    >
      <slot name="actions" />
    </div>
  </article>
</template>

<style scoped>
.gc-project-card {
  min-height: 128px;
  border: 1px solid var(--runne-border);
  border-radius: var(--runne-radius-lg);
  background: var(--runne-surface);
  transition: border-color var(--runne-motion-fast), background var(--runne-motion-fast);
}

.gc-project-card-main {
  display: grid;
  width: 100%;
  min-height: 126px;
  grid-template-columns: auto minmax(0, 1fr) auto;
  align-items: center;
  gap: 15px;
  padding: 18px;
  border: 0;
  border-radius: inherit;
  color: inherit;
  background: transparent;
  text-align: left;
  cursor: pointer;
}

.gc-project-card-main:focus-visible {
  outline: 2px solid var(--runne-accent);
  outline-offset: 3px;
}

.gc-project-card:hover {
  border-color: var(--runne-text-secondary);
  background: var(--runne-surface-raised);
}

.gc-project-card-icon {
  display: grid;
  width: 44px;
  height: 44px;
  place-items: center;
  border-radius: var(--runne-radius-md);
  color: var(--runne-accent);
  background: var(--runne-surface-raised);
}

.gc-project-card-copy,
.gc-project-card-header {
  display: grid;
  gap: 5px;
}

.gc-project-card-header {
  grid-template-columns: minmax(0, 1fr) auto;
  align-items: center;
}

.gc-project-card-name {
  overflow: hidden;
  color: var(--runne-text-primary);
  font-size: 16px;
  font-weight: 650;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.gc-project-card-status {
  padding: 2px 8px;
  border-radius: var(--runne-radius-sm);
  font-size: 11px;
  font-weight: 500;
  letter-spacing: .5px;
  text-transform: uppercase;
}

.gc-project-card-status--ready { color: var(--runne-lead-green); background: color-mix(in srgb, var(--runne-lead-green) 15%, transparent); }
.gc-project-card-status--stale { color: var(--runne-accent); background: color-mix(in srgb, var(--runne-accent) 15%, transparent); }
.gc-project-card-status--recovery { color: var(--runne-error-coral); background: color-mix(in srgb, var(--runne-error-coral) 15%, transparent); }
.gc-project-card--stale { border-color: color-mix(in srgb, var(--runne-accent) 30%, transparent); }
.gc-project-card--recovery { border-color: color-mix(in srgb, var(--runne-error-coral) 30%, transparent); }

.gc-project-card-path,
.gc-project-card-time {
  overflow: hidden;
  color: var(--runne-ui-muted);
  font-size: 12px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.gc-project-card-path { font-family: var(--runne-font-mono); color: var(--runne-ui-subtle); }
.gc-project-card-arrow { display: grid; color: var(--runne-accent); }
.gc-project-card-actions { display: flex; gap: var(--runne-space-sm); padding: 0 18px 18px; }
</style>
