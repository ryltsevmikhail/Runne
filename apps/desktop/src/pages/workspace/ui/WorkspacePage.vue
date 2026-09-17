<script setup lang="ts">
import { GcAlert, GcButton } from '@runne/product/shared/ui'
import { Folder } from 'lucide-vue-next'
import { computed, onBeforeUnmount, ref, shallowRef, watch, type PropType } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { listWorkspaceChanges, readWorkspaceDiff } from '@/entities/diff'
import { getCanonicalWorkspace, isCanonicalRuntimeId } from '@/entities/project'
import { listWorkspaceFiles } from '@/entities/file-tree'
import { openWorkspaceEditor } from '@/features/open-editor'
import { RetryableWorkspaceOpen } from '@/features/open-local-project'
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
import WorkspaceFolderReconnect from './WorkspaceFolderReconnect.vue'
import {
  createWorkspaceRefreshController,
  type WorkspaceRefreshLoaders,
} from '../model/workspace-refresh'
import {
  createFilesRetryController,
  createSingleFlightLoader,
} from '../model/workspace-retry'
type OpenEditor = (id: string, path: string) => Promise<unknown>
const props = defineProps({
  loadProject: {
    type: Function as PropType<WorkspaceRefreshLoaders['loadProject']>,
    default: getCanonicalWorkspace,
  },
  loadFiles: {
    type: Function as PropType<WorkspaceRefreshLoaders['loadFiles']>,
    default: (id: string, path: string, limit: number) => listWorkspaceFiles(id, path, limit),
  },
  loadChanges: {
    type: Function as PropType<WorkspaceRefreshLoaders['loadChanges']>,
    default: (id: string, limit: number) => listWorkspaceChanges(id, limit),
  },
  loadDiff: {
    type: Function as PropType<WorkspaceRefreshLoaders['loadDiff']>,
    default: (id: string, path: string) => readWorkspaceDiff(id, path),
  },
  openEditor: {
    type: Function as PropType<OpenEditor>,
    default: (id: string, path: string) => openWorkspaceEditor(id, path),
  },
})
const route = useRoute()
const router = useRouter()
const runtimeSession = tryUseRuntimeSession()
const runtimeStatus = computed(() => runtimeSession?.snapshot.value.status ?? 'unavailable')
const readOnly = computed(() => runtimeStatus.value !== 'live'
  || runtimeSession?.snapshot.value.canMutate !== true)
const processId = computed(() => {
  const value = route.query.processId
  return typeof value === 'string' && isCanonicalRuntimeId(value) ? value : null
})
const { chunks: processChunks, loading: processLoading, error: processError } = useProcessOutput(processId, runtimeStatus)
const workspaceId = computed(() => typeof route.params.workspaceId === 'string' ? route.params.workspaceId : '')
const refresh = createWorkspaceRefreshController({
  loadProject: props.loadProject,
  loadFiles: props.loadFiles,
  loadChanges: props.loadChanges,
  loadDiff: props.loadDiff,
})
const {
  project, files, filesLoading, filesError, changes, changesLoading, changesError,
  selectedPath, selectedDiff, diffLoading, diffError, loading,
} = refresh
const pendingReconnect = shallowRef<RetryableWorkspaceOpen | null>(null)
const pendingReconnectWorkspaceId = ref<string | null>(null)
const pendingReconnectGeneration = ref<number | null>(null)
const reconnectViewGeneration = ref(0)
const activePendingReconnect = computed(() => pendingReconnectWorkspaceId.value === workspaceId.value
  && pendingReconnectGeneration.value === reconnectViewGeneration.value
  ? pendingReconnect.value
  : null)

function clearPendingReconnect(): void {
  pendingReconnect.value = null
  pendingReconnectWorkspaceId.value = null
  pendingReconnectGeneration.value = null
}

function onReconnectRetryable(value: RetryableWorkspaceOpen, id: string, viewGeneration: number): void {
  if (id !== workspaceId.value || viewGeneration !== reconnectViewGeneration.value
    || value.binding.workspaceId !== id) return
  pendingReconnect.value = value
  pendingReconnectWorkspaceId.value = id
  pendingReconnectGeneration.value = viewGeneration
}

function onReconnectConnected(id: string, viewGeneration: number): void {
  if (id !== workspaceId.value || viewGeneration !== reconnectViewGeneration.value) return
  clearPendingReconnect()
  pageLoads.request(id)
}

function onReconnectFailed(id: string, viewGeneration: number): void {
  if (id === workspaceId.value && viewGeneration === reconnectViewGeneration.value) {
    clearPendingReconnect()
  }
}

async function openFile(path: string) {
  const id = workspaceId.value
  if (readOnly.value || !isCanonicalRuntimeId(id)) return
  await props.openEditor(id, path)
}

let previousWorkspaceId: string | undefined
const pageLoads = createSingleFlightLoader(
  async (id: string) => { await refresh.load(id) },
  (id) => id === workspaceId.value && runtimeStatus.value === 'live',
)
watch([runtimeStatus, workspaceId], ([status, id]) => {
  if (previousWorkspaceId !== undefined && previousWorkspaceId !== id) {
    reconnectViewGeneration.value += 1
    clearPendingReconnect()
    refresh.invalidate()
  }
  previousWorkspaceId = id
  if (runtimeSession === undefined) {
    refresh.markUnavailable()
    return
  }
  if (status === 'live') pageLoads.request(id)
  else refresh.markUnavailable()
}, { immediate: true })
const disposeFilesRetry = createFilesRetryController(
  () => ({
    status: runtimeStatus.value,
    error: filesError.value,
    loading: filesLoading.value || loading.value,
    id: workspaceId.value,
  }),
  (id) => { pageLoads.request(id) },
)
onBeforeUnmount(() => {
  pageLoads.dispose()
  disposeFilesRetry()
  refresh.dispose()
})
async function returnToProjects() {
  await router.push('/')
}
</script>
<template>
  <section
    v-if="project === null && loading"
    class="empty-state"
    aria-live="polite"
  >
    <h1>{{ translate('workspace.loading') }}</h1>
  </section>
  <section
    v-else-if="project === null"
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
        <WorkspaceFolderReconnect
          v-if="filesError || activePendingReconnect !== null"
          :key="project.workspaceId"
          :workspace-id="project.workspaceId"
          :view-generation="reconnectViewGeneration"
          :pending="activePendingReconnect"
          :disabled="readOnly"
          @connected="onReconnectConnected"
          @retryable="onReconnectRetryable"
          @failed="onReconnectFailed"
        />
      </template>
      <template #conversation>
        <div class="workspace-conversation">
          <details class="workspace-conversation__context">
            <summary>{{ translate('workspace.changes') }}</summary>
            <div class="workspace-panel__title-row">
              <h2>{{ translate('workspace.workArea') }}</h2>
              <span v-if="changesLoading">{{ translate('workspace.loadingChanges') }}</span>
            </div>
            <p :aria-live="readOnly ? 'polite' : 'off'">
              {{ readOnly ? translate('workspace.readOnly') : translate('workspace.editable') }}
            </p>
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
                  @click="refresh.selectChange(workspaceId, change.path)"
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
          </details>
          <ConversationChat
            :key="project.workspaceId"
            :workspace-id="project.workspaceId"
            :disabled="readOnly"
          />
          <details
            class="workspace-terminal-disclosure"
            :open="processId !== null"
          >
            <summary>{{ translate('terminal.title') }}</summary>
            <TerminalPanel
              :process-id="processId"
              :chunks="processChunks"
              :loading="processLoading"
              :error="processError || readOnly"
            />
          </details>
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
