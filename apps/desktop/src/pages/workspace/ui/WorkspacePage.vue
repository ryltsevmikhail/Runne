<script setup lang="ts">
import { GcAlert, GcButton } from '@runne/product/shared/ui'
import { Folder } from 'lucide-vue-next'
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import type { CanonicalWorkspace } from '@/entities/project'
import type { WorkspaceChangeEntry, WorkspaceDiff } from '@/entities/diff'
import { listWorkspaceChanges, readWorkspaceDiff } from '@/entities/diff'
import { getCanonicalWorkspace, isCanonicalRuntimeId } from '@/entities/project'
import { listWorkspaceFiles, type WorkspaceFileEntry } from '@/entities/file-tree'
import { openWorkspaceEditor } from '@/features/open-editor'
import { useProcessOutput } from '@/entities/process/model/use-process-output'
import { tryUseRuntimeSession } from '@/app/providers/runtime-session'
import { translate } from '@/shared/i18n'
import { DiffViewer } from '@/widgets/diff-viewer'
import { FileExplorer } from '@/widgets/file-explorer'
import { TerminalPanel } from '@/widgets/terminal'
import { ConversationChat } from '@/widgets/conversation-chat'
import WorkspaceBreadcrumb from './WorkspaceBreadcrumb.vue'
import WorkspaceDetails from './WorkspaceDetails.vue'
import WorkspaceFrame from './WorkspaceFrame.vue'
type LoadProject = (id: string) => Promise<CanonicalWorkspace>
type LoadFiles = (id: string, path: string, limit: number) => Promise<{
  readonly items: readonly WorkspaceFileEntry[]
}>
type LoadChanges = (id: string, limit: number) => Promise<{
  readonly items: readonly WorkspaceChangeEntry[]
}>
type LoadDiff = (id: string, path: string) => Promise<WorkspaceDiff>
type OpenEditor = (id: string, path: string) => Promise<unknown>
const props = withDefaults(defineProps<{
  loadProject?: LoadProject
  loadFiles?: LoadFiles
  loadChanges?: LoadChanges
  loadDiff?: LoadDiff
  openEditor?: OpenEditor
}>(), {
  loadProject: getCanonicalWorkspace,
  loadFiles: (id, path, limit) => listWorkspaceFiles(id, path, limit),
  loadChanges: (id, limit) => listWorkspaceChanges(id, limit),
  loadDiff: (id, path) => readWorkspaceDiff(id, path),
  openEditor: (id, path) => openWorkspaceEditor(id, path),
})
const route = useRoute()
const router = useRouter()
const project = ref<CanonicalWorkspace | null>(null)
const files = ref<readonly WorkspaceFileEntry[]>([])
const filesLoading = ref(false)
const filesError = ref(false)
const changes = ref<readonly WorkspaceChangeEntry[]>([])
const changesLoading = ref(false)
const changesError = ref(false)
const selectedPath = ref<string | null>(null)
const selectedDiff = ref<WorkspaceDiff | null>(null)
const diffLoading = ref(false)
const diffError = ref(false)
const loading = ref(true)
const error = ref(false)
const runtimeSession = tryUseRuntimeSession()
const runtimeStatus = computed(() => runtimeSession?.snapshot.value.status ?? 'unavailable')
const readOnly = computed(() => runtimeStatus.value !== 'live')
const processId = computed(() => {
  const value = route.query.processId
  return typeof value === 'string' && isCanonicalRuntimeId(value) ? value : null
})
const { chunks: processChunks, loading: processLoading, error: processError } = useProcessOutput(processId, runtimeStatus)
async function refreshProject() {
  error.value = false
  loading.value = true
  const id = typeof route.params.workspaceId === 'string' ? route.params.workspaceId : ''
  if (!isCanonicalRuntimeId(id)) {
    error.value = true
    loading.value = false
    return
  }
  try {
    project.value = await props.loadProject(id)
    await refreshFiles(id)
    await refreshChanges(id)
  }
  catch {
    error.value = true
  }
  finally {
    loading.value = false
  }
}
async function refreshChanges(id: string) {
  changesLoading.value = true
  changesError.value = false
  try {
    changes.value = (await props.loadChanges(id, 50)).items
    const nextPath = changes.value[0]?.path ?? null
    selectedPath.value = nextPath
    if (nextPath !== null) await fetchDiff(id, nextPath)
    else selectedDiff.value = null
  }
  catch {
    changes.value = []
    selectedPath.value = null
    selectedDiff.value = null
    changesError.value = true
  }
  finally {
    changesLoading.value = false
  }
}
async function fetchDiff(id: string, path: string) {
  diffLoading.value = true
  diffError.value = false
  try {
    selectedDiff.value = await props.loadDiff(id, path)
  }
  catch {
    selectedDiff.value = null
    diffError.value = true
  }
  finally {
    diffLoading.value = false
  }
}
async function selectChange(path: string) {
  selectedPath.value = path
  const id = typeof route.params.workspaceId === 'string' ? route.params.workspaceId : ''
  if (isCanonicalRuntimeId(id)) await fetchDiff(id, path)
}
async function refreshFiles(id: string) {
  filesLoading.value = true
  filesError.value = false
  try {
    files.value = (await props.loadFiles(id, '', 50)).items
  }
  catch {
    files.value = []
    filesError.value = true
  }
  finally {
    filesLoading.value = false
  }
}
async function openFile(path: string) {
  const id = typeof route.params.workspaceId === 'string' ? route.params.workspaceId : ''
  if (runtimeStatus.value !== 'live' || !isCanonicalRuntimeId(id)) return
  await props.openEditor(id, path)
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
  else if (project.value === null) {
    error.value = true
    loading.value = false
  }
}, { immediate: true })

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
    <h1>{{ translate('workspace.loading') }}</h1>
  </section>
  <section
    v-else-if="error || project === null"
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
    v-else
    class="workspace-page"
    aria-labelledby="workspace-title"
  >
    <header class="workspace-header">
      <WorkspaceBreadcrumb
        :project-id="project.projectId"
        :project-name="project.displayName"
      />
      <span class="workspace-kicker">{{ translate('workspace.kicker') }}</span>
      <h1 id="workspace-title">
        {{ project.displayName }}
      </h1>
      <span class="workspace-status">{{ translate('workspace.workspaceStatus', { status: runtimeStatus }) }}</span>
    </header>
    <WorkspaceFrame>
      <template #explorer>
        <div class="panel-heading">
          <Folder
            :size="15"
            aria-hidden="true"
          />
          <strong>{{ translate('workspace.projectTree') }}</strong>
        </div>
        <FileExplorer
          :entries="files"
          :loading="filesLoading"
          :error="filesError"
          :disabled="readOnly"
          :open-file="openFile"
        />
      </template>

      <template #conversation>
        <div class="workspace-conversation">
          <div class="workspace-conversation__context">
            <div class="workspace-panel__title-row">
              <h2>{{ translate('workspace.workArea') }}</h2>
              <span v-if="changesLoading">{{ translate('workspace.loadingChanges') }}</span>
            </div>
            <p :aria-live="readOnly ? 'polite' : 'off'">
              {{ readOnly ? translate('workspace.readOnly') : translate('workspace.editable') }}
            </p>
            <h3>{{ translate('workspace.changes') }}</h3>
            <p
              v-if="changesError"
              role="alert"
            >
              {{ translate('workspace.changesUnavailable') }}
            </p>
            <ul
              v-else-if="changes.length"
              class="workspace-changes"
              :aria-label="translate('workspace.changesLabel')"
            >
              <li
                v-for="change in changes"
                :key="change.path"
              >
                <button
                  type="button"
                  :aria-pressed="selectedPath === change.path"
                  @click="selectChange(change.path)"
                >
                  <span>{{ change.path }}</span>
                  <small>{{ change.kind }} · +{{ change.additions }} / -{{ change.deletions }}</small>
                </button>
              </li>
            </ul>
            <p v-else-if="!changesLoading">
              {{ translate('workspace.noChanges') }}
            </p>
            <DiffViewer
              :diff="selectedDiff"
              :loading="diffLoading"
              :error="diffError"
            />
          </div>
          <ConversationChat :workspace-id="project.workspaceId" />
          <TerminalPanel
            :process-id="processId"
            :chunks="processChunks"
            :loading="processLoading"
            :error="processError || readOnly"
          />
        </div>
      </template>

      <template #details>
        <WorkspaceDetails
          :project="project"
          :runtime-status="runtimeStatus"
        />
      </template>
    </WorkspaceFrame>
  </section>
</template>
