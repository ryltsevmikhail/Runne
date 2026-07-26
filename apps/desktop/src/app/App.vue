<script setup lang="ts">
import {
  Activity,
  ChevronLeft,
  CircleHelp,
  FolderKanban,
  Moon,
  PanelLeft,
  Settings,
  Sun,
} from 'lucide-vue-next'
import { isTauri } from '@tauri-apps/api/core'
import { onMounted, ref } from 'vue'

import { loadBootstrap, saveTheme } from '@/shared/api/platform/bootstrap'

const theme = ref<'dark' | 'light'>('dark')
const sidebarCollapsed = ref(false)

onMounted(async () => {
  if (isTauri()) {
    const bootstrap = await loadBootstrap()
    theme.value = bootstrap.theme
  }
})

async function toggleTheme() {
  const previous = theme.value
  theme.value = previous === 'dark' ? 'light' : 'dark'
  if (!isTauri()) {
    return
  }
  try {
    await saveTheme(theme.value)
  }
  catch {
    theme.value = previous
  }
}
</script>

<template>
  <div
    class="app-shell"
    :class="{ 'app-shell--collapsed': sidebarCollapsed }"
    :data-theme="theme"
  >
    <aside
      class="sidebar"
      :class="{ 'sidebar--collapsed': sidebarCollapsed }"
    >
      <div class="sidebar-header">
        <RouterLink
          class="brand"
          to="/"
          aria-label="GOCODE home"
        >
          <span class="brand-mark">G</span>
          <span class="brand-name">GOCODE</span>
        </RouterLink>
        <button
          class="icon-button collapse-button"
          type="button"
          :aria-label="sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'"
          @click="sidebarCollapsed = !sidebarCollapsed"
        >
          <PanelLeft
            v-if="sidebarCollapsed"
            :size="16"
            aria-hidden="true"
          />
          <ChevronLeft
            v-else
            :size="16"
            aria-hidden="true"
          />
        </button>
      </div>

      <nav aria-label="Primary">
        <p class="nav-label">
          Workspace
        </p>
        <RouterLink
          class="nav-item"
          to="/"
          title="Projects"
        >
          <FolderKanban
            :size="17"
            aria-hidden="true"
          />
          <span>Projects</span>
        </RouterLink>
        <RouterLink
          class="nav-item"
          to="/settings/runtimes"
          title="Runtime settings"
        >
          <Settings
            :size="17"
            aria-hidden="true"
          />
          <span>Settings</span>
        </RouterLink>
      </nav>

      <div class="sidebar-status">
        <div
          class="runtime-status"
          title="Runtime contract pending"
        >
          <span class="status-dot" />
          <span class="status-copy">
            <strong>Runtime offline</strong>
            <small>Contract pending</small>
          </span>
        </div>

        <div class="sidebar-actions">
          <button
            class="icon-button"
            type="button"
            aria-label="Diagnostics"
            title="Diagnostics"
          >
            <Activity
              :size="16"
              aria-hidden="true"
            />
          </button>
          <button
            class="icon-button"
            type="button"
            aria-label="Help"
            title="Help"
          >
            <CircleHelp
              :size="16"
              aria-hidden="true"
            />
          </button>
          <button
            class="icon-button"
            type="button"
            :aria-label="theme === 'dark' ? 'Use light theme' : 'Use dark theme'"
            :title="theme === 'dark' ? 'Use light theme' : 'Use dark theme'"
            @click="toggleTheme"
          >
            <Sun
              v-if="theme === 'dark'"
              :size="16"
              aria-hidden="true"
            />
            <Moon
              v-else
              :size="16"
              aria-hidden="true"
            />
          </button>
        </div>
      </div>
    </aside>

    <main class="workspace">
      <RouterView />
    </main>
  </div>
</template>
