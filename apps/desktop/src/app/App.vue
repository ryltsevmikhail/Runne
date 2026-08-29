<script setup lang="ts">
import {
  Activity,
  ChevronLeft,
  CircleHelp,
  FolderKanban,
  ListChecks,
  Moon,
  PanelLeft,
  Settings,
  Sun,
} from 'lucide-vue-next'
import { GcSidebar } from '@gocode/product/shared/ui'
import '@gocode/product/shared/ui/styles/tokens.css'
import '@gocode/product/shared/ui/styles/base.css'
import { isTauri } from '@tauri-apps/api/core'
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import {
  connectRuntime,
  loadBootstrap,
  saveTheme,
} from '@/shared/api/platform/bootstrap'
import type { RuntimeConnectionState } from '@/shared/api/platform/bootstrap'
import type {
  RuntimeFailureCode,
  RuntimeLifecycleStatus,
  RuntimeMode,
} from '@/shared/api/platform/bootstrap'
import brandLockup from '@/shared/assets/OPea5.png'
import brandIcon from '@/shared/assets/x4q5w.png'
import brandLockupLight from '@/shared/assets/r6geR.png'
import brandIconLight from '@/shared/assets/C9sQTI.png'
import { DesktopTitleBar } from '@/widgets/desktop-title-bar'
import { RuntimeStatus } from '@/widgets/runtime-status'

const SIDEBAR_STORAGE_KEY = 'runne:sidebar-collapsed'
const THEME_STORAGE_KEY = 'runne:theme'
const storedTheme = typeof localStorage !== 'undefined' ? localStorage.getItem(THEME_STORAGE_KEY) : null

const theme = ref<'dark' | 'light'>(storedTheme === 'light' ? 'light' : 'dark')
const runtimeState = ref<RuntimeConnectionState>('unconfigured')
const runtimeMode = ref<RuntimeMode>('external_local')
const runtimeLifecycle = ref<RuntimeLifecycleStatus>('external')
const runtimeFailure = ref<RuntimeFailureCode | null>(null)
const sidebarCollapsed = ref(typeof localStorage !== 'undefined' && localStorage.getItem(SIDEBAR_STORAGE_KEY) === 'true')
const compactViewport = ref(false)
const sidebarIsCollapsed = computed(() => sidebarCollapsed.value || compactViewport.value)
const route = useRoute()
const router = useRouter()

const sidebarItems = [
  { id: 'projects', label: 'Projects', icon: FolderKanban },
  { id: 'task-runs', label: 'Task Runs', icon: ListChecks },
  { id: 'diagnostics', label: 'Diagnostics', icon: Activity },
  { id: 'settings', label: 'Settings', icon: Settings },
]
const activeSidebarItem = computed(() => {
  if (route.path.startsWith('/task-runs')) return 'task-runs'
  if (route.path === '/diagnostics' || route.path === '/settings/diagnostics') return 'diagnostics'
  if (route.path.startsWith('/settings')) return 'settings'
  return 'projects'
})
let runtimePoll: ReturnType<typeof setInterval> | undefined
let compactViewportQuery: MediaQueryList | undefined

function syncCompactViewport(event: MediaQueryList | MediaQueryListEvent): void {
  compactViewport.value = event.matches
}

function applyBootstrap(bootstrap: Awaited<ReturnType<typeof loadBootstrap>>) {
  theme.value = bootstrap.theme
  runtimeMode.value = bootstrap.runtimeMode
  runtimeState.value = bootstrap.runtime
  runtimeLifecycle.value = bootstrap.runtimeLifecycle
  runtimeFailure.value = bootstrap.runtimeFailure
}

async function refreshRuntimeStatus() {
  try {
    applyBootstrap(await loadBootstrap())
  }
  catch {
    runtimeLifecycle.value = 'failed'
    runtimeFailure.value = null
  }
}

onMounted(async () => {
  if (typeof window.matchMedia === 'function') {
    compactViewportQuery = window.matchMedia('(max-width: 1023px)')
    syncCompactViewport(compactViewportQuery)
    compactViewportQuery.addEventListener('change', syncCompactViewport)
  }

  if (isTauri()) {
    await refreshRuntimeStatus()
    try {
      runtimeState.value = await connectRuntime()
    }
    catch {
      // The next sanitized bootstrap refresh carries the closed failure code.
    }
    await refreshRuntimeStatus()
    runtimePoll = setInterval(() => {
      void refreshRuntimeStatus()
    }, 1_000)
  }
})

watch(sidebarCollapsed, (collapsed) => {
  if (typeof localStorage !== 'undefined') localStorage.setItem(SIDEBAR_STORAGE_KEY, String(collapsed))
})

onBeforeUnmount(() => {
  compactViewportQuery?.removeEventListener('change', syncCompactViewport)
  if (runtimePoll !== undefined) {
    clearInterval(runtimePoll)
  }
})

async function toggleTheme() {
  const previous = theme.value
  theme.value = previous === 'dark' ? 'light' : 'dark'
  if (!isTauri()) {
    if (typeof localStorage !== 'undefined') localStorage.setItem(THEME_STORAGE_KEY, theme.value)
    return
  }
  try {
    await saveTheme(theme.value)
  }
  catch {
    theme.value = previous
  }
}

async function navigateSidebar(id: string) {
  const destinations: Record<string, string> = {
    projects: '/',
    'task-runs': '/task-runs',
    diagnostics: '/diagnostics',
    settings: '/settings/runtimes',
  }
  await router.push(destinations[id] ?? '/')
}
</script>

<template>
  <div
    class="app-shell"
    :class="{ 'app-shell--collapsed': sidebarIsCollapsed }"
    :data-theme="theme"
  >
    <DesktopTitleBar />

    <aside
      class="sidebar"
      :class="{ 'sidebar--collapsed': sidebarIsCollapsed }"
    >
      <div class="sidebar-header">
        <RouterLink
          class="brand"
          to="/"
          aria-label="Runne home"
        >
          <img
            class="brand-lockup brand-lockup--dark"
            :src="brandLockup"
            alt=""
          >
          <img
            class="brand-lockup brand-lockup--light"
            :src="brandLockupLight"
            alt=""
          >
          <img
            class="brand-icon brand-icon--dark"
            :src="brandIcon"
            alt=""
          >
          <img
            class="brand-icon brand-icon--light"
            :src="brandIconLight"
            alt=""
          >
        </RouterLink>
        <button
          class="icon-button collapse-button"
          type="button"
          :aria-label="sidebarIsCollapsed ? 'Expand sidebar' : 'Collapse sidebar'"
          @click="sidebarCollapsed = !sidebarCollapsed"
        >
          <PanelLeft
            v-if="sidebarIsCollapsed"
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

      <GcSidebar
        class="app-sidebar-navigation"
        :items="sidebarItems"
        :active-item="activeSidebarItem"
        :collapsed="sidebarIsCollapsed"
        aria-label="Primary"
        @navigate="navigateSidebar"
      />

      <div class="sidebar-status">
        <RuntimeStatus
          :mode="runtimeMode"
          :connection="runtimeState"
          :lifecycle="runtimeLifecycle"
          :failure="runtimeFailure"
        />

        <div class="sidebar-actions">
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
