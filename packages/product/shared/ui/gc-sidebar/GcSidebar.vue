<script setup lang="ts">
import type { Component } from 'vue'

import primaryLogo from '../assets/runne-primary-logo.svg'
import primaryLogoLight from '../assets/runne-primary-logo-light.svg'
import routeGlyph from '../assets/runne-route-glyph.svg'

export interface SidebarItem {
  id: string
  label: string
  icon?: Component
  badge?: string
}

defineProps<{
  items: SidebarItem[]
  activeItem?: string
  collapsed?: boolean
  ariaLabel?: string
}>()

defineEmits<{
  navigate: [id: string]
}>()
</script>

<template>
  <nav
    :class="['gc-sidebar', collapsed && 'gc-sidebar--collapsed']"
    :aria-label="ariaLabel ?? 'Primary'"
  >
    <div class="gc-sidebar-brand-header">
      <button
        class="gc-sidebar-brand"
        type="button"
        aria-label="Runne"
        @click="$emit('navigate', 'projects')"
      >
        <img
          class="gc-sidebar-brand-lockup gc-sidebar-brand-lockup--dark"
          :src="primaryLogo"
          alt="Runne"
        >
        <img
          class="gc-sidebar-brand-lockup gc-sidebar-brand-lockup--light"
          :src="primaryLogoLight"
          alt="Runne"
        >
        <span class="gc-sidebar-brand-glyph-shell">
          <img
            class="gc-sidebar-brand-glyph"
            :src="routeGlyph"
            alt=""
          >
        </span>
      </button>
      <slot name="actions" />
    </div>
    <template
      v-for="item in items"
      :key="item.id"
    >
      <button
        :data-nav-id="item.id"
        :class="['gc-sidebar-item', { 'gc-sidebar-item--active': item.id === activeItem }]"
        type="button"
        :aria-label="item.label"
        @click="$emit('navigate', item.id)"
      >
        <component
          :is="item.icon"
          v-if="item.icon"
          class="gc-sidebar-icon"
          :size="18"
          aria-hidden="true"
        />
        <span
          v-if="!collapsed"
          class="gc-sidebar-label"
        >{{ item.label }}</span>
        <span
          v-if="!collapsed && item.badge"
          class="gc-sidebar-badge"
        >{{ item.badge }}</span>
      </button>
      <slot
        name="after-item"
        :item="item"
      />
    </template>
  </nav>
</template>

<style scoped>
.gc-sidebar {
  display: flex;
  flex-direction: column;
  width: 240px;
  padding: var(--runne-space-sm);
  gap: 2px;
  background: var(--runne-sidebar);
  border-right: 1px solid var(--runne-border);
}

.gc-sidebar--collapsed {
  width: 56px;
}

.gc-sidebar-brand-header {
  display: flex;
  min-height: 32px;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  margin-bottom: 24px;
}

.gc-sidebar-brand {
  display: flex;
  min-width: 0;
  align-items: center;
  padding-left: 2px;
  border: 0;
  background: transparent;
  cursor: pointer;
}

.gc-sidebar-brand-lockup {
  display: block;
  width: 112px;
  height: auto;
}

.gc-sidebar-brand-glyph-shell {
  display: none;
  width: 28px;
  height: 28px;
  padding: 4px;
  border-radius: var(--runne-radius-md);
  background: var(--runne-accent);
}

.gc-sidebar-brand-glyph {
  display: block;
  width: 100%;
  height: 100%;
}

.gc-sidebar-brand-lockup--light {
  display: none;
}

.gc-sidebar--collapsed .gc-sidebar-brand-header {
  justify-content: center;
}

.gc-sidebar--collapsed .gc-sidebar-brand {
  padding-left: 0;
}

.gc-sidebar--collapsed .gc-sidebar-brand-lockup {
  display: none;
}

.gc-sidebar--collapsed .gc-sidebar-brand-glyph-shell {
  display: block;
}

:global([data-theme='light'] .gc-sidebar-brand-lockup--dark) {
  display: none;
}

:global([data-theme='light'] .gc-sidebar-brand-lockup--light) {
  display: block;
}

.gc-sidebar--collapsed .gc-sidebar-brand-lockup--light {
  display: none;
}

.gc-sidebar-item {
  display: flex;
  align-items: center;
  gap: var(--runne-space-sm);
  padding: 8px var(--runne-space-md);
  border-radius: var(--runne-radius-md);
  border: none;
  background: transparent;
  color: var(--runne-text-secondary);
  font-family: var(--runne-font-ui);
  font-size: 14px;
  cursor: pointer;
  transition: background var(--runne-motion-fast), color var(--runne-motion-fast);
  text-align: left;
  width: 100%;
}

.gc-sidebar-item:hover {
  background: var(--runne-surface);
  color: var(--runne-text-primary);
}

.gc-sidebar-item--active {
  background: var(--runne-surface);
  color: var(--runne-text-primary);
  font-weight: 500;
}

.gc-sidebar-icon {
  flex-shrink: 0;
}

.gc-sidebar-label {
  flex: 1;
}

.gc-sidebar-badge {
  font-size: 11px;
  padding: 2px 6px;
  border-radius: var(--runne-radius-sm);
  background: color-mix(in srgb, var(--runne-accent) 20%, transparent);
  color: var(--runne-accent);
}
</style>
