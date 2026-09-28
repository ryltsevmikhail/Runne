<script setup lang="ts">
import { ChevronRight, Folder, MessageSquare, Plus } from 'lucide-vue-next'
import { onBeforeUnmount, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { createCanonicalWorkspace, getCanonicalProject, openCanonicalWorkspace, type CanonicalProject, type CanonicalWorkspace } from '@/entities/project'
import { openProjectWorkspace, ProjectWorkspaceOpenError } from '@/features/open-project-workspace'
import { ProjectManagement } from '@/features/manage-project'
import ProjectTrustControl from './ProjectTrustControl.vue'
import { translate } from '@/shared/i18n'

const props = defineProps<{
  project: CanonicalProject; active: boolean; disabled: boolean; destructiveDisabled?: boolean | undefined
  loadProject?: typeof getCanonicalProject | undefined
  openWorkspace?: typeof openCanonicalWorkspace | undefined
  createWorkspace?: typeof createCanonicalWorkspace | undefined
}>()
const route = useRoute()
const router = useRouter()
const expanded = ref(false)
const workspaces = ref<readonly CanonicalWorkspace[]>()
const loading = ref(false)
const busy = ref(false)
const treeError = ref(false)
const openError = ref(false)
let epoch = 0
let loadGeneration = 0
let alive = true
onBeforeUnmount(() => { alive = false; epoch += 1; loadGeneration += 1 })
watch(() => route.fullPath, () => { epoch += 1 })
watch(() => props.active, active => { if (active) { expanded.value = true; void load() } }, { immediate: true })
watch(() => props.project.version, () => { if (expanded.value) void load() })

async function load() {
  if (props.disabled || props.project.archived) return
  const generation = ++loadGeneration
  loading.value = true
  treeError.value = false
  try {
    const result = await (props.loadProject ?? getCanonicalProject)(props.project.projectId)
    if (alive && generation === loadGeneration && !props.disabled) workspaces.value = result.workspaces
  }
  catch { if (alive && generation === loadGeneration) treeError.value = true }
  finally { if (alive && generation === loadGeneration) loading.value = false }
}
async function toggle() {
  expanded.value = !expanded.value
  if (expanded.value) await load()
}
function isCurrent(generation: number) {
  return alive && generation === epoch && !props.disabled
}
async function openProject() {
  if (busy.value || props.disabled) return
  const generation = epoch
  busy.value = true
  openError.value = false
  try {
    await openProjectWorkspace(
      props.project,
      () => isCurrent(generation),
      {
        openWorkspace: async workspaceId => {
          if (!isCurrent(generation)) throw new ProjectWorkspaceOpenError()
          await router.push({ name: 'workspace', params: { workspaceId } })
        },
        openProjectDetails: async projectId => {
          if (!isCurrent(generation)) throw new ProjectWorkspaceOpenError()
          await router.push({ name: 'project-details', params: { projectId } })
        },
      },
      props.loadProject,
      props.openWorkspace,
    )
  }
  catch { if (isCurrent(generation)) openError.value = true }
  finally { busy.value = false }
}
async function open(workspace: CanonicalWorkspace) {
  if (busy.value || props.disabled || props.project.archived) return
  const generation = epoch
  busy.value = true
  openError.value = false
  try {
    if (!workspace.open) await (props.openWorkspace ?? openCanonicalWorkspace)(workspace.workspaceId, workspace.version)
    if (alive && generation === epoch && !props.disabled) await router.push({ name: 'workspace', params: { workspaceId: workspace.workspaceId } })
  }
  catch { if (alive && generation === epoch) openError.value = true }
  finally { busy.value = false }
}
async function create() {
  if (busy.value || props.disabled || props.project.archived) return
  const generation = epoch
  busy.value = true
  openError.value = false
  try {
    const created = await (props.createWorkspace ?? createCanonicalWorkspace)(props.project.projectId, 'Workspace')
    if (alive && generation === epoch && !props.disabled) await router.push({ name: 'workspace', params: { workspaceId: created.workspaceId } })
  }
  catch { if (alive && generation === epoch) openError.value = true }
  finally { busy.value = false }
}
async function removed() { if (props.active) await router.push('/') }
</script>

<template>
  <li class="project-tree-item">
    <div class="project-tree-row">
      <button type="button" class="project-tree-toggle" :aria-expanded="expanded"
        :aria-label="translate(expanded ? 'projects.collapseProjectTree' : 'projects.expandProjectTree', { name: project.displayName })"
        :disabled="disabled || busy"
        @click="toggle">
        <ChevronRight :size="12" class="project-tree-chevron" :class="{ expanded }" aria-hidden="true" />
      </button>
      <button type="button" class="project-tree-open" :class="{ 'project-tree-open--active': active }"
        :aria-current="active && typeof route.params.workspaceId !== 'string' ? 'page' : undefined"
        :aria-label="translate('projects.openProject', { name: project.displayName })" :disabled="disabled || busy"
        @click="openProject">
        <Folder :size="14" aria-hidden="true" />
        <span>{{ project.displayName }}</span>
      </button>
      <ProjectManagement :project="project" :disabled="disabled || busy || destructiveDisabled" @removed="removed" />
      <button v-if="openError" type="button" class="project-tree-open-error" @click="openProject">
        {{ translate('settings.retry') }}
      </button>
      <p v-if="openError" class="project-tree-error" role="alert">{{ translate('projects.openWorkspaceFailed') }}</p>
    </div>
    <div v-if="expanded" class="project-tree-children">
      <p v-if="project.archived" class="project-tree-note">{{ translate('projects.archived') }}</p>
      <p v-else-if="loading && !workspaces" class="project-tree-note">{{ translate('projects.loading') }}</p>
      <template v-else-if="workspaces">
        <ul>
          <li v-for="workspace in workspaces" :key="workspace.workspaceId">
            <button type="button" class="project-tree-workspace" :disabled="disabled || busy"
              :aria-label="translate('projectDetails.openWorkspace', { name: workspace.displayName })"
              :aria-current="route.params.workspaceId === workspace.workspaceId ? 'page' : undefined"
              @click="open(workspace)">
              <MessageSquare :size="13" aria-hidden="true" /><span>{{ workspace.displayName }}</span>
            </button>
            <ProjectTrustControl v-if="route.params.workspaceId === workspace.workspaceId && workspace.open && !project.archived"
              :project-id="project.projectId" :workspace-id="workspace.workspaceId" :disabled="disabled || busy" />
          </li>
        </ul>
        <button type="button" class="project-tree-create" :disabled="disabled || busy" @click="create">
          <Plus :size="13" aria-hidden="true" />{{ translate('projectDetails.createWorkspace') }}
        </button>
      </template>
      <button v-if="treeError" type="button" class="project-tree-note" @click="load">{{ translate('settings.retry') }}</button>
      <p v-if="treeError" class="project-tree-error" role="alert">{{ translate('projects.openWorkspaceFailed') }}</p>
    </div>
  </li>
</template>

<style scoped>
.project-tree-item { min-width: 0; }
.project-tree-row { display: grid; grid-template-columns: 20px minmax(0, 1fr) 28px; align-items: center; }
.project-tree-row :deep(.project-menu__trigger) { width: 28px; height: 28px; }
.project-tree-toggle, .project-tree-open, .project-tree-workspace, .project-tree-create {
  display: flex; align-items: center; gap: 6px; min-width: 0; width: 100%; min-height: 28px;
  padding: 4px 6px; border: 0; border-radius: 5px; background: transparent;
  color: var(--runne-text-secondary); font: inherit; font-size: 12px; text-align: left; cursor: pointer;
}
.project-tree-toggle { justify-content: center; padding-inline: 2px; }
.project-tree-open span, .project-tree-workspace span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
svg { flex: 0 0 auto; }
.project-tree-chevron.expanded { transform: rotate(90deg); }
.project-tree-children { margin-left: 20px; }
ul { list-style: none; padding: 0; margin: 0; }
.project-tree-open[aria-current="page"], .project-tree-open--active, .project-tree-workspace[aria-current="page"],
.project-tree-toggle:hover:not(:disabled), .project-tree-open:hover:not(:disabled), .project-tree-workspace:hover:not(:disabled),
.project-tree-create:hover:not(:disabled) { background: var(--runne-surface-raised); color: var(--runne-text-primary); }
.project-tree-create { font-size: 11px; opacity: .75; }
.project-tree-note, .project-tree-error { margin: 4px 6px; font-size: 11px; color: var(--runne-text-secondary); }
.project-tree-open-error { grid-column: 2 / -1; padding: 0 6px; border: 0; background: transparent; font: inherit; font-size: 11px; text-align: left; text-decoration: underline; cursor: pointer; }
.project-tree-row > .project-tree-error { grid-column: 2 / -1; }
.project-tree-error { color: var(--runne-error-coral); }
button:disabled { opacity: .5; cursor: default; }
button:focus-visible { outline: 2px solid var(--runne-accent); outline-offset: -2px; }
</style>
