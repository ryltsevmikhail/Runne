<script setup lang="ts">
import { GcAlert, GcButton, GcDialog } from '@runne/product/shared/ui'
import { isTauri } from '@tauri-apps/api/core'
import { ArrowRight, FolderOpen } from 'lucide-vue-next'
import { computed, nextTick, onBeforeUnmount, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import type { CanonicalProjectDetails, CanonicalProjectDestructiveOperation, CanonicalProjectDestructiveOutcome, CanonicalWorkspaceMutationAck } from '@/entities/project'
import { renameCanonicalProject, createCanonicalWorkspace, executeCanonicalProjectDestructiveAction, getCanonicalProject, isCanonicalRuntimeId, openCanonicalWorkspace } from '@/entities/project'
import { tryUseRuntimeSession } from '@/app/providers/runtime-session'
import { translate } from '@/shared/i18n'
import { ProjectActionsMenu, RenameProjectDialog } from '@/features/manage-project'

type LoadProject = (id: string) => Promise<CanonicalProjectDetails>
type CreateWorkspace = (projectId: string, displayName: string) => Promise<CanonicalWorkspaceMutationAck>
type OpenWorkspace = (workspaceId: string, expectedVersion: number) => Promise<CanonicalWorkspaceMutationAck>
type DestructiveProjectAction = (projectId: string, expectedVersion: number, operation: CanonicalProjectDestructiveOperation) => Promise<CanonicalProjectDestructiveOutcome | void>

const props = withDefaults(defineProps<{
  loadProject?: LoadProject
  createWorkspaceMutation?: CreateWorkspace
  openWorkspaceMutation?: OpenWorkspace
  destructiveProjectAction?: DestructiveProjectAction
}>(), {
  loadProject: getCanonicalProject,
  createWorkspaceMutation: createCanonicalWorkspace,
  openWorkspaceMutation: openCanonicalWorkspace,
  destructiveProjectAction: executeCanonicalProjectDestructiveAction,
})

const route = useRoute()
const router = useRouter()
const details = ref<CanonicalProjectDetails | null>(null)
const loading = ref(true)
const renaming = ref(false)
const actionsMenu = ref<InstanceType<typeof ProjectActionsMenu>>()
async function closeRename() { renaming.value = false; await nextTick(); actionsMenu.value?.focus() }
const error = ref(false)
const creatingWorkspace = ref(false)
const createWorkspaceError = ref(false)
const openWorkspaceError = ref(false)
const openingWorkspaceId = ref<string | null>(null)
const destructiveOperation = ref<CanonicalProjectDestructiveOperation | null>(null)
const destructiveConfirmation = ref<CanonicalProjectDestructiveOperation | null>(null)
const destructiveError = ref(false)
const runtimeSession = tryUseRuntimeSession()
const runtimeStatus = computed(() => runtimeSession?.snapshot.value.status ?? 'unavailable')
let generation = 0
let navigationGeneration = 0
onBeforeUnmount(() => {
  generation += 1
  navigationGeneration += 1
})

function currentProjectId() {
  return typeof route.params.projectId === 'string' ? route.params.projectId : ''
}

function isCurrentNavigation(token: number, projectId: string) {
  return token === navigationGeneration
    && currentProjectId() === projectId
    && runtimeStatus.value === 'live'
}

async function refreshProject() {
  const request = ++generation
  error.value = false
  loading.value = true
  const id = typeof route.params.projectId === 'string' ? route.params.projectId : ''
  if (!isCanonicalRuntimeId(id)) {
    error.value = true
    loading.value = false
    return
  }
  try {
    const result = await props.loadProject(id)
    if (request === generation && route.params.projectId === id) details.value = result
  }
  catch {
    if (request === generation) error.value = true
  }
  finally {
    if (request === generation) loading.value = false
  }
}

watch([runtimeStatus, () => route.params.projectId], ([status]) => {
  navigationGeneration += 1
  generation += 1
  renaming.value = false
  openingWorkspaceId.value = null
  creatingWorkspace.value = false
  destructiveOperation.value = null
  destructiveConfirmation.value = null
  details.value = null
  if (runtimeSession === undefined) {
    error.value = true
    loading.value = false
    return
  }
  if (status === 'live') {
    void refreshProject()
  }
  else if (details.value === null) {
    error.value = true
    loading.value = false
  }
}, { immediate: true })

async function openWorkspace(workspaceId: string) {
  const projectId = currentProjectId()
  const token = navigationGeneration
  const selected = details.value?.workspaces.find(workspace => workspace.workspaceId === workspaceId)
  if (selected === undefined || !isCurrentNavigation(token, projectId) || openingWorkspaceId.value !== null) return
  openWorkspaceError.value = false
  openingWorkspaceId.value = workspaceId
  try {
    if (!selected.open) {
      await props.openWorkspaceMutation(workspaceId, selected.version)
      if (!isCurrentNavigation(token, projectId)) return
      await refreshProject()
      if (!isCurrentNavigation(token, projectId)) return
    }
    if (!isCurrentNavigation(token, projectId)) return
    await router.push({
      name: 'workspace',
      params: { workspaceId },
    })
  }
  catch {
    if (isCurrentNavigation(token, projectId)) openWorkspaceError.value = true
  }
  finally {
    if (token === navigationGeneration && openingWorkspaceId.value === workspaceId) openingWorkspaceId.value = null
  }
}

async function createWorkspace() {
  const id = currentProjectId()
  const token = navigationGeneration
  if (!isCanonicalRuntimeId(id) || !isCurrentNavigation(token, id) || creatingWorkspace.value) return
  creatingWorkspace.value = true
  createWorkspaceError.value = false
  try {
    await props.createWorkspaceMutation(id, 'Workspace')
    if (!isCurrentNavigation(token, id)) return
    await refreshProject()
    if (!isCurrentNavigation(token, id)) return
  }
  catch {
    if (isCurrentNavigation(token, id)) createWorkspaceError.value = true
  }
  finally {
    if (token === navigationGeneration) creatingWorkspace.value = false
  }
}

async function runDestructiveAction(operation: CanonicalProjectDestructiveOperation) {
  const id = currentProjectId()
  const token = navigationGeneration
  const project = details.value?.project
  if (!isCanonicalRuntimeId(id) || project === undefined || !isCurrentNavigation(token, id) || destructiveOperation.value !== null) return
  destructiveError.value = false
  destructiveOperation.value = operation
  try {
    const outcome = await props.destructiveProjectAction(id, project.version, operation)
    if (outcome === 'cancelled') return
    if (!isCurrentNavigation(token, id)) return
    if (operation === 'delete') {
      await returnToProjects()
    }
    else {
      await refreshProject()
      if (!isCurrentNavigation(token, id)) return
    }
  }
  catch {
    if (isCurrentNavigation(token, id)) destructiveError.value = true
  }
  finally {
    if (token === navigationGeneration) destructiveOperation.value = null
  }
}
async function executeDestructiveAction(operation: CanonicalProjectDestructiveOperation) {
  if (!isTauri()) {
    destructiveConfirmation.value = operation
    return
  }
  await runDestructiveAction(operation)
}
async function confirmDestructiveAction() {
  const operation = destructiveConfirmation.value
  if (operation === null) return
  destructiveConfirmation.value = null
  await runDestructiveAction(operation)
}
async function cancelDestructiveAction() {
  destructiveConfirmation.value = null
  await nextTick()
  actionsMenu.value?.focus()
}

async function renameProject(name: string) {
  const project = details.value?.project
  const token = navigationGeneration
  if (!project || project.projectId !== currentProjectId() || !isCurrentNavigation(token, project.projectId)) throw new Error('Unavailable')
  await renameCanonicalProject(project.projectId, project.version, name)
  if (!isCurrentNavigation(token, project.projectId)) return
  renaming.value = false
  await refreshProject()
  if (!isCurrentNavigation(token, project.projectId)) return
  await closeRename()
}
async function returnToProjects() {
  await router.push('/')
}
</script>

<template>
  <section
    v-if="loading"
    class="empty-state"
    aria-live="polite"
  >
    <h1>{{ translate('projectDetails.loading') }}</h1>
  </section>
  <section
    v-else-if="error || details === null"
    class="empty-state"
    role="alert"
  >
    <GcAlert
      level="error"
      :title="translate('projectDetails.unavailable')"
    >
      {{ translate('projectDetails.restoreMessage') }}
    </GcAlert>
    <GcButton
      variant="secondary"
      @click="returnToProjects"
    >
      {{ translate('projectDetails.back') }}
    </GcButton>
  </section>
  <section
    v-else-if="details !== null"
    aria-labelledby="project-title"
  >
    <header class="page-header">
      <div>
        <span class="workspace-kicker">{{ translate('projectDetails.kicker') }}</span>
        <h1 id="project-title">
          {{ details.project.displayName }}
        </h1>
        <p>{{ translate('projectDetails.version', { version: details.project.version }) }}</p>
        <p class="runtime-summary">
          {{ translate('projectDetails.runtimeSummary', { status: runtimeStatus }) }}
        </p>
      </div>
      <ProjectActionsMenu
        ref="actionsMenu"
        :archived="details.project.archived"
        :disabled="runtimeStatus !== 'live' || destructiveOperation !== null || destructiveConfirmation !== null"
        @action="executeDestructiveAction"
        @rename="renaming = true"
      />
    </header>
    <GcDialog
      v-if="destructiveConfirmation !== null"
      :open="true"
      :title="translate(destructiveConfirmation === 'delete' ? 'projects.confirmDeleteTitle' : 'projects.confirmArchiveTitle')"
      :description="translate(destructiveConfirmation === 'delete' ? 'projects.confirmDeleteMessage' : 'projects.confirmArchiveMessage', { name: details.project.displayName })"
      :confirm-label="translate('projects.confirm')"
      :cancel-label="translate('projects.cancel')"
      :danger="destructiveConfirmation === 'delete'"
      @confirm="confirmDestructiveAction"
      @cancel="cancelDestructiveAction"
    />
    <RenameProjectDialog
      v-if="renaming"
      :name="details.project.displayName"
      :save="renameProject"
      @close="closeRename"
    />
    <p
      v-if="destructiveError"
      role="alert"
    >
      {{ translate('projectDetails.destructiveActionFailed') }}
    </p>
    <GcAlert
      v-if="details.project.archived"
      level="warning"
      :title="translate('projectDetails.archived')"
    >
      {{ translate('projectDetails.archivedMessage') }}
    </GcAlert>
    <div
      v-else
      class="content-section"
    >
      <div class="section-heading">
        <h2>{{ translate('projectDetails.workspaces') }}</h2>
        <span>{{ translate('projectDetails.runtime') }}</span>
      </div>
      <p
        v-if="openWorkspaceError"
        role="alert"
      >
        {{ translate('projectDetails.openWorkspaceFailed') }}
      </p>
      <div
        v-if="details.workspaces.length === 0"
        class="content-section"
      >
        <p>{{ translate('projectDetails.noWorkspaces') }}</p>
        <GcButton
          :aria-label="translate('projectDetails.createWorkspace')"
          :disabled="creatingWorkspace || runtimeStatus !== 'live'"
          @click="createWorkspace"
        >
          {{ creatingWorkspace ? translate('projectDetails.creatingWorkspace') : translate('projectDetails.createWorkspace') }}
        </GcButton>
        <p
          v-if="createWorkspaceError"
          role="alert"
        >
          {{ translate('projectDetails.createWorkspaceFailed') }}
        </p>
      </div>
      <button
        v-for="workspace in details.workspaces"
        :key="workspace.workspaceId"
        class="project-card project-card--workspace"
        type="button"
        :aria-label="translate('projectDetails.openWorkspace', { name: workspace.displayName })"
        :disabled="runtimeStatus !== 'live' || openingWorkspaceId !== null"
        @click="openWorkspace(workspace.workspaceId)"
      >
        <span class="project-icon">
          <FolderOpen
            :size="21"
            aria-hidden="true"
          />
        </span>
        <span class="project-copy">
          <strong>{{ openingWorkspaceId === workspace.workspaceId ? translate('projectDetails.openingWorkspace') : workspace.displayName }}</strong>
          <small>{{ translate('projectDetails.workspaceVersion', {
            version: workspace.version,
            state: workspace.open ? translate('projectDetails.open') : translate('projectDetails.closed'),
          }) }}</small>
        </span>
        <ArrowRight
          class="project-arrow"
          :size="16"
          aria-hidden="true"
        />
      </button>
    </div>
  </section>
</template>
