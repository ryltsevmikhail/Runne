<script setup lang="ts">
import {
  Activity,
  ChevronLeft,
  CircleHelp,
  FolderKanban,
  History,
  Moon,
  PanelLeft,
  Settings,
  Sun,
} from 'lucide-vue-next'
import { GcSidebar } from '@runne/product/shared/ui'
import '@runne/product/shared/ui/styles/tokens.css'
import '@runne/product/shared/ui/styles/base.css'
import { isTauri } from '@tauri-apps/api/core'
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import {
  connectRuntime,
  loadBootstrap,
  saveTheme,
} from '@/shared/api/platform/bootstrap'
import {
  createRuntimeSessionContext,
  createRuntimeSessionController,
  provideRuntimeSession,
} from '@/app/providers/runtime-session'
import type { RuntimeConnectionState } from '@/shared/api/platform/bootstrap'
import type {
  RuntimeFailureCode,
  RuntimeLifecycleStatus,
  RuntimeMode,
} from '@/shared/api/platform/bootstrap'
import { DesktopTitleBar } from '@/widgets/desktop-title-bar'
import { RuntimeStatus } from '@/widgets/runtime-status'
import { appTheme } from '@/shared/model/theme'
import {
  listenExternalActivation,
  loadPendingExternalActivation,
  type ActivationTarget,
} from '@/shared/api/platform/external-activation'
import { syncNotifications } from '@/shared/api/platform/notifications'
import { loadOwnedLocale, translate } from '@/shared/i18n'
const theme = appTheme
const runtimeState = ref<RuntimeConnectionState>('unconfigured')
const runtimeMode = ref<RuntimeMode>('external_local')
const runtimeLifecycle = ref<RuntimeLifecycleStatus>('external')
const runtimeFailure = ref<RuntimeFailureCode | null>(null)
const activationNotice = ref<string | null>(null)
const sidebarCollapsed = ref(false)
const route = useRoute()
const router = useRouter()
const runtimeSession = createRuntimeSessionContext(createRuntimeSessionController({
  connect: connectRuntime,
  loadBootstrap,
}))
provideRuntimeSession(runtimeSession)

const sidebarItems = computed(() => [
  { id: 'projects', label: translate('projects.title'), icon: FolderKanban },
  { id: 'task-runs', label: 'Task runs', icon: History },
  { id: 'settings', label: translate('settings.title'), icon: Settings },
])
const activeSidebarItem = computed(() => route.path.startsWith('/settings')
  ? 'settings'
  : route.path.startsWith('/task-runs') ? 'task-runs' : 'projects')
let runtimePoll: ReturnType<typeof setInterval> | undefined
let notificationPoll: ReturnType<typeof setInterval> | undefined
let stopExternalActivation: (() => void) | undefined

function applyBootstrap(bootstrap: Awaited<ReturnType<typeof loadBootstrap>>) {
  theme.value = bootstrap.theme
  runtimeMode.value = bootstrap.runtimeMode
  runtimeState.value = bootstrap.runtime
  runtimeLifecycle.value = bootstrap.runtimeLifecycle
  runtimeFailure.value = bootstrap.runtimeFailure
  runtimeSession.observeBootstrap(bootstrap)
}

async function refreshRuntimeStatus() {
  try {
    applyBootstrap(await loadBootstrap())
  }
  catch {
    runtimeLifecycle.value = 'failed'
    runtimeFailure.value = null
    runtimeSession.observeBootstrap({ runtime: 'fatal' })
  }
}

async function openExternalActivation(target: ActivationTarget) {
  if (runtimeState.value !== 'live') return
  if (target.runtime !== null) {
    activationNotice.value = translate('activation.runtimeReconciliationRequired')
    return
  }
  if (target.taskRunId !== null) {
    await router.push({ name: 'task-run', params: { taskRunId: target.taskRunId } })
  }
  else if (target.approvalId !== null || target.event === 'approval') {
    await router.push({ name: 'approvals' })
  }
  else if (target.workspaceId !== null) {
    await router.push({ name: 'workspace', params: { workspaceId: target.workspaceId } })
  }
  else if (target.projectId !== null) {
    await router.push({ name: 'project-details', params: { projectId: target.projectId } })
  }
  else {
    activationNotice.value = translate('activation.surfaceUnavailable')
  }
}

const pendingActivation = ref<ActivationTarget | null>(null)
watch(runtimeState, () => {
  if (pendingActivation.value === null || runtimeState.value !== 'live') return
  const target = pendingActivation.value
  pendingActivation.value = null
  void openExternalActivation(target)
})

function receiveExternalActivation(target: ActivationTarget) {
  pendingActivation.value = target
  if (runtimeState.value === 'live') {
    pendingActivation.value = null
    void openExternalActivation(target)
  }
}

onMounted(async () => {
  if (isTauri()) {
    try {
      await loadOwnedLocale()
      stopExternalActivation = await listenExternalActivation(receiveExternalActivation)
      const pending = await loadPendingExternalActivation()
      if (pending !== null) receiveExternalActivation(pending)
    }
    catch {
      activationNotice.value = translate('activation.unavailable')
    }
    await runtimeSession.connect()
    await refreshRuntimeStatus()
    void syncNotifications().catch(() => undefined)
    runtimePoll = setInterval(() => {
      void refreshRuntimeStatus()
    }, 1_000)
    notificationPoll = setInterval(() => {
      void syncNotifications().catch(() => undefined)
    }, 15_000)
  }
})

onBeforeUnmount(() => {
  void runtimeSession.close()
  stopExternalActivation?.()
  if (runtimePoll !== undefined) {
    clearInterval(runtimePoll)
  }
  if (notificationPoll !== undefined) {
    clearInterval(notificationPoll)
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
  await router.push(id === 'settings' ? '/settings/runtimes' : id === 'task-runs' ? '/task-runs' : '/')
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
      <GcSidebar
        class="app-sidebar-navigation"
        :items="sidebarItems"
        :active-item="activeSidebarItem"
        :collapsed="sidebarCollapsed"
        :aria-label="translate('navigation.primary')"
        @navigate="navigateSidebar"
      >
        <template #actions>
          <button
            class="icon-button collapse-button"
            type="button"
            :aria-label="sidebarCollapsed ? translate('navigation.expandSidebar') : translate('navigation.collapseSidebar')"
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
        </template>
      </GcSidebar>

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
            :aria-label="translate('navigation.diagnostics')"
            :title="translate('navigation.diagnostics')"
          >
            <Activity
              :size="16"
              aria-hidden="true"
            />
          </RouterLink>
          <button
            class="icon-button"
            type="button"
            :aria-label="translate('navigation.help')"
            :title="translate('navigation.help')"
          >
            <CircleHelp
              :size="16"
              aria-hidden="true"
            />
          </button>
          <button
            class="icon-button"
            type="button"
            :aria-label="theme === 'dark' ? translate('navigation.useLightTheme') : translate('navigation.useDarkTheme')"
            :title="theme === 'dark' ? translate('navigation.useLightTheme') : translate('navigation.useDarkTheme')"
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
      <p
        v-if="activationNotice !== null"
        class="app-shell__activation-notice"
        role="alert"
      >
        {{ activationNotice }}
      </p>
      <RouterView />
    </main>
  </div>
</template>
