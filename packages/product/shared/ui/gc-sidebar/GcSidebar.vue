<script setup lang="ts">
import type { Component } from 'vue'
import { nextTick, ref } from 'vue'

export interface SidebarItem {
  id: string
  label: string
  icon?: string | Component
  badge?: string
}

defineProps<{
  items: SidebarItem[]
  activeItem?: string
  collapsed?: boolean
  ariaLabel?: string
}>()

const emit = defineEmits<{
  navigate: [id: string]
}>()

const itemButtons = ref<HTMLButtonElement[]>([])

function focusItem(index: number): void {
  void nextTick(() => itemButtons.value[index]?.focus())
}

function handleKeydown(event: KeyboardEvent, index: number, count: number): void {
  if (event.key === 'ArrowDown') {
    event.preventDefault()
    focusItem((index + 1) % count)
  }
  else if (event.key === 'ArrowUp') {
    event.preventDefault()
    focusItem((index - 1 + count) % count)
  }
  else if (event.key === 'Home') {
    event.preventDefault()
    focusItem(0)
  }
  else if (event.key === 'End') {
    event.preventDefault()
    focusItem(count - 1)
  }
}
</script>

<template>
  <nav
    :class="['gc-sidebar', collapsed && 'gc-sidebar--collapsed']"
    :aria-label="ariaLabel ?? 'Primary'"
  >
    <button
      v-for="(item, index) in items"
      :key="item.id"
      ref="itemButtons"
      :class="['gc-sidebar-item', { 'gc-sidebar-item--active': item.id === activeItem }]"
      type="button"
      :aria-label="collapsed ? item.label : undefined"
      :aria-current="item.id === activeItem ? 'page' : undefined"
      :data-tooltip="collapsed ? item.label : undefined"
      :title="collapsed ? item.label : undefined"
      @click="emit('navigate', item.id)"
      @keydown="handleKeydown($event, index, items.length)"
    >
      <component
        :is="item.icon"
        v-if="item.icon && typeof item.icon !== 'string'"
        class="gc-sidebar-icon"
        :size="18"
        aria-hidden="true"
      />
      <span
        v-else-if="item.icon"
        class="gc-sidebar-icon"
        aria-hidden="true"
      >{{ item.icon }}</span>
      <span
        v-if="!collapsed"
        class="gc-sidebar-label"
      >{{ item.label }}</span>
      <span
        v-if="!collapsed && item.badge"
        class="gc-sidebar-badge"
      >{{ item.badge }}</span>
    </button>
  </nav>
</template>

<style scoped>
.gc-sidebar {
  display: flex;
  flex-direction: column;
  width: 100%;
  padding: var(--gocode-space-sm);
  gap: 4px;
  background: var(--gocode-sidebar);
  border-right: 1px solid var(--gocode-border);
}


.gc-sidebar-item {
  position: relative;
  display: flex;
  min-height: 40px;
  align-items: center;
  gap: var(--gocode-space-sm);
  padding: 8px var(--gocode-space-md);
  border: 0;
  border-radius: var(--gocode-radius-md);
  color: var(--gocode-text-secondary);
  background: transparent;
  font-family: var(--gocode-font-ui);
  font-size: 14px;
  text-align: left;
  cursor: pointer;
  transition: background var(--gocode-motion-fast), color var(--gocode-motion-fast), transform 100ms ease;
}

.gc-sidebar--collapsed .gc-sidebar-item {
  justify-content: center;
  padding-inline: 8px;
}

.gc-sidebar--collapsed .gc-sidebar-icon {
  width: 18px;
}

.gc-sidebar-item:hover {
  color: var(--gocode-text-primary);
  background: var(--gocode-surface);
}

.gc-sidebar-item:active {
  transform: translateY(1px) scale(.99);
}

.gc-sidebar-item:focus-visible {
  z-index: 1;
  outline: 2px solid var(--gocode-accent);
  outline-offset: 2px;
  color: var(--gocode-text-primary);
}

.gc-sidebar-item--active {
  color: var(--gocode-text-primary);
  background: var(--gocode-surface);
  font-weight: 600;
}

.gc-sidebar-item--active::before {
  position: absolute;
  top: 8px;
  bottom: 8px;
  left: 0;
  width: 3px;
  border-radius: 2px;
  background: var(--gocode-accent);
  content: '';
}

.gc-sidebar--collapsed .gc-sidebar-item::after {
  position: absolute;
  z-index: 20;
  top: 50%;
  left: calc(100% + 10px);
  padding: 6px 9px;
  border: 1px solid var(--gocode-border);
  border-radius: var(--gocode-radius-sm);
  color: var(--gocode-text-primary);
  background: var(--gocode-surface-raised);
  box-shadow: 0 8px 24px rgb(0 0 0 / 20%);
  content: attr(data-tooltip);
  font-size: 12px;
  font-weight: 500;
  line-height: 1;
  white-space: nowrap;
  opacity: 0;
  pointer-events: none;
  transform: translate(4px, -50%);
  transition: opacity var(--gocode-motion-fast), transform var(--gocode-motion-fast);
}

.gc-sidebar--collapsed .gc-sidebar-item:hover::after,
.gc-sidebar--collapsed .gc-sidebar-item:focus-visible::after {
  opacity: 1;
  transform: translate(0, -50%);
}

.gc-sidebar-icon {
  width: 24px;
  flex-shrink: 0;
  text-align: center;
}

.gc-sidebar-label {
  flex: 1;
}

.gc-sidebar-badge {
  padding: 2px 6px;
  border-radius: var(--gocode-radius-sm);
  color: var(--gocode-accent);
  background: color-mix(in srgb, var(--gocode-accent) 20%, transparent);
  font-size: 11px;
}

@media (prefers-reduced-motion: reduce) {
  .gc-sidebar-item,
  .gc-sidebar-item::after {
    transition: none;
  }
}
</style>
