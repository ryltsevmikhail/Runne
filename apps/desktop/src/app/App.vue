<script setup lang="ts">
import {
  Activity,
  ChevronLeft,
  CircleHelp,
  Moon,
  PanelLeft,
  Sun,
} from 'lucide-vue-next'
import { GcSidebar } from '@gocode/product/shared/ui'
import '@gocode/product/shared/ui/styles/tokens.css'
import '@gocode/product/shared/ui/styles/base.css'
import { isTauri } from '@tauri-apps/api/core'
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
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
import brandIcon from '@/shared/assets/gocode-app-icon.png'
import brandLockup from '@/shared/assets/gocode-lockup.png'
import { DesktopTitleBar } from '@/widgets/desktop-title-bar'
import { RuntimeStatus } from '@/widgets/runtime-status'

const theme = ref<'dark' | 'light'>('dark')
const runtimeState = ref<RuntimeConnectionState>('unconfigured')
const runtimeMode = ref<RuntimeMode>('external_local')
const runtimeLifecycle = ref<RuntimeLifecycleStatus>('external')
const runtimeFailure = ref<RuntimeFailureCode | null>(null)
const sidebarCollapsed = ref(false)
const route = useRoute()
const router = useRouter()

const sidebarItems = [
  { id: 'projects', label: 'Projects', icon: '▦' },
  { id: 'settings', label: 'Settings', icon: '⚙' },
]
const activeSidebarItem = computed(() => route.path.startsWith('/settings') ? 'settings' : 'projects')
let runtimePoll: ReturnType<typeof setInterval> | undefined

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

onBeforeUnmount(() => {
  if (runtimePoll !== undefined) {
    clearInterval(runtimePoll)
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

async function navigateSidebar(id: string) {
  await router.push(id === 'settings' ? '/settings/runtimes' : '/')
}
</script>

<template>
  <div
    class="app-shell"
    :class="{ 'app-shell--collapsed': sidebarCollapsed }"
    :data-theme="theme"
  >
    <DesktopTitleBar />

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
          <img
            class="brand-lockup"
            :src="brandLockup"
            alt=""
          >
          <img
            class="brand-icon"
            :src="brandIcon"
            alt=""
          >
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

      <GcSidebar
        class="app-sidebar-navigation"
        :items="sidebarItems"
        :active-item="activeSidebarItem"
        :collapsed="sidebarCollapsed"
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
          <RouterLink
            class="icon-button"
            to="/settings/diagnostics"
            aria-label="Diagnostics"
            title="Diagnostics"
          >
            <Activity
              :size="16"
              aria-hidden="true"
            />
          </RouterLink>
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
