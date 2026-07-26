<script setup lang="ts">
export interface SidebarItem {
  id: string
  label: string
  icon?: string
  badge?: string
}

defineProps<{
  items: SidebarItem[]
  activeItem?: string
  collapsed?: boolean
}>()

defineEmits<{
  navigate: [id: string]
}>()
</script>

<template>
  <nav :class="['gc-sidebar', collapsed && 'gc-sidebar--collapsed']">
    <button
      v-for="item in items"
      :key="item.id"
      :class="['gc-sidebar-item', { 'gc-sidebar-item--active': item.id === activeItem }]"
      @click="$emit('navigate', item.id)"
    >
      <span v-if="item.icon" class="gc-sidebar-icon">{{ item.icon }}</span>
      <span v-if="!collapsed" class="gc-sidebar-label">{{ item.label }}</span>
      <span v-if="!collapsed && item.badge" class="gc-sidebar-badge">{{ item.badge }}</span>
    </button>
  </nav>
</template>

<style scoped>
.gc-sidebar {
  display: flex;
  flex-direction: column;
  width: 240px;
  padding: var(--gocode-space-sm);
  gap: 2px;
  background: var(--gocode-sidebar);
  border-right: 1px solid var(--gocode-border);
}

.gc-sidebar--collapsed {
  width: 56px;
}

.gc-sidebar-item {
  display: flex;
  align-items: center;
  gap: var(--gocode-space-sm);
  padding: 8px var(--gocode-space-md);
  border-radius: var(--gocode-radius-md);
  border: none;
  background: transparent;
  color: var(--gocode-text-secondary);
  font-family: var(--gocode-font-ui);
  font-size: 14px;
  cursor: pointer;
  transition: background var(--gocode-motion-fast), color var(--gocode-motion-fast);
  text-align: left;
  width: 100%;
}

.gc-sidebar-item:hover {
  background: var(--gocode-surface);
  color: var(--gocode-text-primary);
}

.gc-sidebar-item--active {
  background: var(--gocode-surface);
  color: var(--gocode-text-primary);
  font-weight: 500;
}

.gc-sidebar-icon {
  font-size: 18px;
  width: 24px;
  text-align: center;
  flex-shrink: 0;
}

.gc-sidebar-label {
  flex: 1;
}

.gc-sidebar-badge {
  font-size: 11px;
  padding: 2px 6px;
  border-radius: var(--gocode-radius-sm);
  background: color-mix(in srgb, var(--gocode-accent) 20%, transparent);
  color: var(--gocode-accent);
}
</style>
