<script setup lang="ts">
import { GcAlert, GcButton } from '@runne/product/shared/ui'
import { ArrowRight, FolderOpen } from 'lucide-vue-next'
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import type { CanonicalProjectDetails, CanonicalProjectDestructiveOperation, CanonicalWorkspaceMutationAck } from '@/entities/project'
import { createCanonicalWorkspace, executeCanonicalProjectDestructiveAction, getCanonicalProject, isCanonicalRuntimeId, openCanonicalWorkspace } from '@/entities/project'
import { tryUseRuntimeSession } from '@/app/providers/runtime-session'
import { translate } from '@/shared/i18n'

type LoadProject = (id: string) => Promise<CanonicalProjectDetails>
type CreateWorkspace = (projectId: string, displayName: string) => Promise<CanonicalWorkspaceMutationAck>
type OpenWorkspace = (workspaceId: string, expectedVersion: number) => Promise<CanonicalWorkspaceMutationAck>
type DestructiveProjectAction = (projectId: string, expectedVersion: number, operation: CanonicalProjectDestructiveOperation) => Promise<void>

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
const error = ref(false)
const creatingWorkspace = ref(false)
const createWorkspaceError = ref(false)
const openWorkspaceError = ref(false)
const openingWorkspaceId = ref<string | null>(null)
const destructiveOperation = ref<CanonicalProjectDestructiveOperation | null>(null)
const destructiveError = ref(false)
const runtimeSession = tryUseRuntimeSession()
const runtimeStatus = computed(() => runtimeSession?.snapshot.value.status ?? 'unavailable')

async function refreshProject() {
  error.value = false
  loading.value = true
  const id = typeof route.params.projectId === 'string' ? route.params.projectId : ''
  if (!isCanonicalRuntimeId(id)) {
    error.value = true
    loading.value = false
    return
  }
  try {
    details.value = await props.loadProject(id)
  }
  catch {
    error.value = true
  }
  finally {
    loading.value = false
  }
}

watch(runtimeStatus, status => {
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
  const selected = details.value?.workspaces.find(workspace => workspace.workspaceId === workspaceId)
  if (selected === undefined || runtimeStatus.value !== 'live' || openingWorkspaceId.value !== null) return
  openWorkspaceError.value = false
  openingWorkspaceId.value = workspaceId
  try {
    if (!selected.open) {
      await props.openWorkspaceMutation(workspaceId, selected.version)
      await refreshProject()
    }
  }
  catch {
    openWorkspaceError.value = true
    return
  }
  finally {
    openingWorkspaceId.value = null
  }
  await router.push({
    name: 'workspace',
    params: { workspaceId },
  })
}

async function createWorkspace() {
  const id = typeof route.params.projectId === 'string' ? route.params.projectId : ''
  if (!isCanonicalRuntimeId(id) || runtimeStatus.value !== 'live' || creatingWorkspace.value) return
  creatingWorkspace.value = true
  createWorkspaceError.value = false
  try {
    await props.createWorkspaceMutation(id, 'Workspace')
    await refreshProject()
  }
  catch {
    createWorkspaceError.value = true
  }
  finally {
    creatingWorkspace.value = false
  }
}

async function executeDestructiveAction(operation: CanonicalProjectDestructiveOperation) {
  const id = typeof route.params.projectId === 'string' ? route.params.projectId : ''
  const project = details.value?.project
  if (!isCanonicalRuntimeId(id) || project === undefined || runtimeStatus.value !== 'live' || destructiveOperation.value !== null) return
  destructiveError.value = false
  destructiveOperation.value = operation
  try {
    await props.destructiveProjectAction(id, project.version, operation)
    if (operation === 'delete') {
      await returnToProjects()
    }
    else {
      await refreshProject()
    }
  }
  catch {
    destructiveError.value = true
  }
  finally {
    destructiveOperation.value = null
  }
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

  <section v-else-if="details !== null" aria-labelledby="project-title">
    <header class="page-header">
      <div>
        <span class="workspace-kicker">{{ translate('projectDetails.kicker') }}</span>
        <h1 id="project-title">
          {{ details.project.displayName }}
        </h1>
        <p>{{ translate('projectDetails.version', { version: details.project.version }) }}</p>
        <p class="runtime-summary">{{ translate('projectDetails.runtimeSummary', { status: runtimeStatus }) }}</p>
      </div>
      <div class="project-actions">
        <GcButton
          v-if="!details.project.archived"
          variant="secondary"
          :aria-label="translate('projectDetails.archiveProject')"
          :disabled="runtimeStatus !== 'live' || destructiveOperation !== null"
          @click="executeDestructiveAction('archive')"
        >
          {{ destructiveOperation === 'archive' ? translate('projectDetails.archivingProject') : translate('projectDetails.archiveProject') }}
        </GcButton>
        <GcButton
          variant="delete"
          :aria-label="translate('projectDetails.deleteProject')"
          :disabled="runtimeStatus !== 'live' || destructiveOperation !== null"
          @click="executeDestructiveAction('delete')"
        >
          {{ destructiveOperation === 'delete' ? translate('projectDetails.deletingProject') : translate('projectDetails.deleteProject') }}
        </GcButton>
      </div>
    </header>
    <p v-if="destructiveError" role="alert">{{ translate('projectDetails.destructiveActionFailed') }}</p>

    <GcAlert v-if="details.project.archived" level="warning" :title="translate('projectDetails.archived')">
      {{ translate('projectDetails.archivedMessage') }}
    </GcAlert>

    <div v-else class="content-section">
      <div class="section-heading">
        <h2>{{ translate('projectDetails.workspaces') }}</h2>
        <span>{{ translate('projectDetails.runtime') }}</span>
      </div>
      <p v-if="openWorkspaceError" role="alert">{{ translate('projectDetails.openWorkspaceFailed') }}</p>
      <div v-if="details.workspaces.length === 0" class="content-section">
        <p>{{ translate('projectDetails.noWorkspaces') }}</p>
        <GcButton
          :aria-label="translate('projectDetails.createWorkspace')"
          :disabled="creatingWorkspace || runtimeStatus !== 'live'"
          @click="createWorkspace"
        >
          {{ creatingWorkspace ? translate('projectDetails.creatingWorkspace') : translate('projectDetails.createWorkspace') }}
        </GcButton>
        <p v-if="createWorkspaceError" role="alert">{{ translate('projectDetails.createWorkspaceFailed') }}</p>
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
