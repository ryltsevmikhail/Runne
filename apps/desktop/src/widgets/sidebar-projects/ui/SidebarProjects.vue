<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { tryUseRuntimeSession } from '@/app/providers/runtime-session'
import { createCanonicalWorkspace, getCanonicalProject, getCanonicalWorkspace, listCanonicalProjects, openCanonicalWorkspace, projectsRevision, type CanonicalProject } from '@/entities/project'
import { translate } from '@/shared/i18n'
import SidebarProjectItem from './SidebarProjectItem.vue'

const props = defineProps<{
  collapsed: boolean
  activeProjectId?: string | undefined
  loadProjects?: typeof listCanonicalProjects | undefined
  loadProject?: typeof getCanonicalProject | undefined
  loadWorkspace?: typeof getCanonicalWorkspace | undefined
  openWorkspace?: typeof openCanonicalWorkspace | undefined
  createWorkspace?: typeof createCanonicalWorkspace | undefined
}>()
const route = useRoute()
const projects = ref<readonly CanonicalProject[]>([])
const loading = ref(false)
const loadError = ref(false)
const retrying = ref(false)
const workspaceProject = ref<string>()
const runtimeSession = tryUseRuntimeSession()
const runtimeStatus = computed(() => runtimeSession?.snapshot.value.status ?? 'unavailable')
const projectSelectionId = computed(() => route.path === '/' && typeof route.query.project === 'string' ? route.query.project : undefined)
const activeProjectId = computed(() => props.activeProjectId ?? projectSelectionId.value ?? workspaceProject.value)
const selectionUnavailable = computed(() => {
  const selected = projectSelectionId.value
  return runtimeStatus.value === 'live'
    && !loading.value
    && !loadError.value
    && typeof selected === 'string'
    && selected.length > 0
    && !projects.value.some(project => project.projectId === selected)
})
let generation = 0
let routeGeneration = 0
async function refreshProjects() {
  const current = ++generation
  if (runtimeStatus.value !== 'live') { projects.value = []; loading.value = false; loadError.value = true; return }
  loading.value = true
  loadError.value = false
  try {
    const loaded = await (props.loadProjects ?? listCanonicalProjects)()
    if (current === generation && runtimeStatus.value === 'live') projects.value = loaded
  }
  catch { if (current === generation) loadError.value = true }
  finally { if (current === generation) loading.value = false }
}
async function resolveActiveProject() {
  const current = ++routeGeneration
  workspaceProject.value = undefined
  const id = route.params.workspaceId
  if (typeof id !== 'string' || runtimeStatus.value !== 'live') return
  try {
    const workspace = await (props.loadWorkspace ?? getCanonicalWorkspace)(id)
    if (current === routeGeneration) workspaceProject.value = workspace.projectId
  }
  catch { /* The workspace route owns its unavailable state. */ }
}
watch(projectsRevision, () => { void refreshProjects() })
watch([runtimeStatus, () => route.fullPath], () => {
  void refreshProjects()
  void resolveActiveProject()
}, { immediate: true })
onBeforeUnmount(() => { generation += 1; routeGeneration += 1 })
async function retryProjects() {
  if (retrying.value) return
  retrying.value = true
  try {
    if (runtimeStatus.value === 'live') await refreshProjects()
    else if (runtimeSession) await runtimeSession.retry()
  }
  catch { loadError.value = true }
  finally { retrying.value = false }
}
</script>

<template>
  <section v-show="!collapsed" class="sidebar-projects" :aria-label="translate('projects.title')">
    <RouterLink class="sidebar-projects__text-chat" to="/text-chat">
      {{ translate('conversation.textOnlyNavigation') }}
    </RouterLink>
    <p v-if="loadError" class="sidebar-projects__error" role="alert">
      {{ translate(runtimeStatus === 'live' ? 'projects.loadFailed' : 'projects.runtimeUnavailable') }}
    </p>
    <p v-if="selectionUnavailable" class="sidebar-projects__error" role="alert">
      {{ translate('projects.selectionUnavailable') }}
    </p>
    <button v-if="loadError && runtimeSession" type="button" class="sidebar-projects__retry"
      :disabled="retrying" @click="retryProjects">{{ translate('settings.retry') }}</button>
    <p v-if="loading && projects.length === 0" class="sidebar-projects__status" aria-live="polite">{{ translate('projects.loading') }}</p>
    <ul class="sidebar-projects__list">
      <SidebarProjectItem v-for="project in projects" :key="project.projectId" :project="project"
        :active="activeProjectId === project.projectId" :disabled="runtimeStatus !== 'live'"
        :destructive-disabled="typeof route.params.workspaceId === 'string'
          && (workspaceProject === undefined || workspaceProject !== project.projectId)"
        :load-project="loadProject" :open-workspace="openWorkspace" :create-workspace="createWorkspace" />
    </ul>
  </section>
</template>

<style scoped>
.sidebar-projects { display: flex; min-height: 0; flex: 1; flex-direction: column; margin: 8px 0; overflow: auto; border-top: 1px solid var(--runne-border); }
.sidebar-projects__list { display: grid; gap: 3px; margin: 6px 0; padding: 0; list-style: none; }
.sidebar-projects__text-chat { margin: 8px 6px 2px; color: var(--runne-text-secondary); font-size: 12px; text-decoration: none; }
.sidebar-projects__retry { align-self: flex-start; margin: 0 6px 6px; padding: 2px 0; border: 0; color: var(--runne-text-secondary); background: transparent; font: inherit; font-size: 11px; text-decoration: underline; cursor: pointer; }
.sidebar-projects__status, .sidebar-projects__error { margin: 6px; color: var(--runne-text-secondary); font-size: 11px; line-height: 1.4; }
.sidebar-projects__error { color: var(--runne-error-coral); }
</style>
