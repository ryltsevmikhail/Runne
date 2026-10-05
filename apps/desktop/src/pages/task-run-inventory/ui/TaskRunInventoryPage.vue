<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch, type PropType } from 'vue'
import { RouterLink } from 'vue-router'
import { getCanonicalProject, listCanonicalProjects } from '@/entities/project'
import type { CanonicalProject, CanonicalProjectDetails } from '@/entities/project'
import { listManagedTaskRuns } from '@/entities/task-run'
import type { ManagedTaskRunsSnapshot } from '@/entities/task-run'
import { tryUseRuntimeSession } from '@/app/providers/runtime-session'
import { translate } from '@/shared/i18n'
import { buildTaskRunTree, type TaskRunTree } from '../model/task-run-tree'

const props = defineProps({
  runtimeReady: { type: Boolean, default: undefined },
  loadRuns: { type: Function as PropType<typeof listManagedTaskRuns>, default: listManagedTaskRuns },
  loadProjects: { type: Function as PropType<typeof listCanonicalProjects>, default: listCanonicalProjects },
  loadProject: { type: Function as PropType<typeof getCanonicalProject>, default: getCanonicalProject },
})
const MAX_PROJECTS = 256
const runtimeSession = tryUseRuntimeSession()
const runtimeStatus = computed(() => props.runtimeReady === undefined
  ? runtimeSession?.snapshot.value.status ?? 'unavailable'
  : props.runtimeReady ? 'live' : 'unavailable')
const tree = ref<TaskRunTree | null>(null)
const loading = ref(true)
const unavailable = ref(false)
let request = 0

async function refresh() {
  const current = ++request
  tree.value = null
  unavailable.value = false
  if (runtimeStatus.value !== 'live') { loading.value = false; unavailable.value = true; return }
  loading.value = true
  try {
    const runs: ManagedTaskRunsSnapshot = await props.loadRuns()
    if (current !== request) return
    if (runs.status !== 'available') throw new Error('Inventory unavailable')
    const projects: readonly CanonicalProject[] = await props.loadProjects()
    if (current !== request || runtimeStatus.value !== 'live') return
    if (projects.length > MAX_PROJECTS) throw new Error('Project snapshot exceeds view bound')
    const details: readonly CanonicalProjectDetails[] = await Promise.all(projects.map(project => props.loadProject(project.projectId)))
    if (current !== request || runtimeStatus.value !== 'live') return
    tree.value = buildTaskRunTree(projects, details, runs.taskRuns)
  } catch { if (current === request) unavailable.value = true }
  finally { if (current === request) loading.value = false }
}

watch(runtimeStatus, status => { if (status === 'live') void refresh(); else { request += 1; loading.value = false; unavailable.value = true } }, { immediate: true })
onBeforeUnmount(() => { request += 1 })
</script>

<template>
  <section class="task-run-inventory-page" aria-labelledby="task-run-inventory-title">
    <header class="task-run-inventory-page__header">
      <h1 id="task-run-inventory-title">{{ translate('taskRunInventory.title') }}</h1>
      <p>{{ translate('taskRunInventory.subtitle') }}</p>
      <RouterLink :to="{ name: 'approvals' }">{{ translate('taskRunInventory.attentionInbox') }}</RouterLink>
    </header>
    <p v-if="loading" aria-live="polite">{{ translate('taskRunInventory.loading') }}</p>
    <p v-else-if="unavailable" role="status">{{ translate('taskRunInventory.unavailable') }}</p>
    <p v-else-if="tree?.projects.length === 0 && tree.unmapped.length === 0">{{ translate('taskRunInventory.empty') }}</p>
    <ul v-else class="task-run-tree">
      <li v-for="project in tree?.projects ?? []" :key="project.projectId">
        <strong>{{ translate('taskRunInventory.project') }}: {{ project.projectName }}</strong>
        <ul>
          <li v-for="workspace in project.workspaces" :key="workspace.workspaceId">
            <strong>{{ translate('taskRunInventory.workspace') }}: {{ workspace.workspaceName }}</strong>
            <ul>
              <li v-for="run in workspace.taskRuns" :key="run.taskRunId">
                <RouterLink :to="{ name: 'task-run', params: { taskRunId: run.taskRunId } }">{{ translate('taskRunInventory.openRun') }} · {{ run.taskRunId }}</RouterLink>
                <span>{{ translate('taskRunInventory.state') }}: {{ run.terminal ?? run.state }}</span>
              </li>
            </ul>
          </li>
        </ul>
      </li>
      <li v-if="tree?.unmapped.length" :aria-label="translate('taskRunInventory.workspaceUnavailable')">
        <strong>{{ translate('taskRunInventory.workspaceUnavailable') }}</strong>
        <ul><li v-for="run in tree.unmapped" :key="run.taskRunId"><RouterLink :to="{ name: 'task-run', params: { taskRunId: run.taskRunId } }">{{ translate('taskRunInventory.openRun') }} · {{ run.taskRunId }}</RouterLink><span>{{ translate('taskRunInventory.state') }}: {{ run.terminal ?? run.state }}</span></li></ul>
      </li>
    </ul>
  </section>
</template>
