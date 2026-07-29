<script setup lang="ts">
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
    @click.self="$emit('click')"
  >
    <button class="gc-project-card-main" type="button" @click="$emit('click')">
      <div class="gc-project-card-header">
        <h3 class="gc-project-card-name">{{ project.name }}</h3>
        <span v-if="project.status" :class="['gc-project-card-status', `gc-project-card-status--${project.status}`]">
          {{ project.status === 'ready' ? 'Ready' : project.status === 'stale' ? 'Attention' : 'Recovery' }}
        </span>
      </div>
      <p class="gc-project-card-path">{{ project.path }}</p>
    </button>
    <div class="gc-project-card-footer">
      <time class="gc-project-card-time">{{ project.modifiedAt }}</time>
      <div v-if="$slots.actions" class="gc-project-card-actions">
        <slot name="actions" />
      </div>
    </div>
  </article>
</template>

<style scoped>
.gc-project-card {
  background: var(--gocode-surface);
  border: 1px solid var(--gocode-border);
  border-radius: var(--gocode-radius-lg);
  padding: var(--gocode-space-lg);
  transition: border-color var(--gocode-motion-fast), background var(--gocode-motion-fast);
}

.gc-project-card-main {
  display: block;
  width: 100%;
  padding: 0;
  color: inherit;
  text-align: left;
  background: transparent;
  border: 0;
  cursor: pointer;
}

.gc-project-card-main:focus-visible {
  outline: 2px solid var(--gocode-accent);
  outline-offset: 3px;
}

.gc-project-card:hover {
  border-color: var(--gocode-text-secondary);
  background: var(--gocode-surface-raised);
}

.gc-project-card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: var(--gocode-space-sm);
}

.gc-project-card-name {
  font-size: 15px;
  font-weight: 600;
  color: var(--gocode-text-primary);
  margin: 0;
}

.gc-project-card-status {
  font-size: 11px;
  font-weight: 500;
  padding: 2px 8px;
  border-radius: var(--gocode-radius-sm);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.gc-project-card-status--ready {
  background: color-mix(in srgb, var(--gocode-lead-green) 15%, transparent);
  color: var(--gocode-lead-green);
}

.gc-project-card-status--stale {
  background: color-mix(in srgb, var(--gocode-accent) 15%, transparent);
  color: var(--gocode-accent);
}

.gc-project-card-status--recovery {
  background: color-mix(in srgb, var(--gocode-error-coral) 15%, transparent);
  color: var(--gocode-error-coral);
}

.gc-project-card--stale {
  border-color: color-mix(in srgb, var(--gocode-accent) 30%, transparent);
}

.gc-project-card--recovery {
  border-color: color-mix(in srgb, var(--gocode-error-coral) 30%, transparent);
}

.gc-project-card-path {
  font-size: 12px;
  color: var(--gocode-ui-subtle);
  margin: 0 0 var(--gocode-space-sm);
  font-family: var(--gocode-font-mono);
}

.gc-project-card-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.gc-project-card-time {
  font-size: 12px;
  color: var(--gocode-ui-muted);
}

.gc-project-card-actions {
  display: flex;
  gap: var(--gocode-space-sm);
}
</style>
