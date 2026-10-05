<script setup lang="ts">
import { onBeforeUnmount, ref, watch } from 'vue'
import { getCanonicalWorkspace } from '@/entities/project'
import { prepareManagedTaskRun, recoverManagedTaskRun, startManagedTaskRun } from '@/entities/task-run'
import { TaskComposer } from '@/features/task-composer'

const props = withDefaults(defineProps<{
  workspaceId: string
  disabled?: boolean
  loadWorkspace?: typeof getCanonicalWorkspace
  prepare?: typeof prepareManagedTaskRun
  start?: typeof startManagedTaskRun
  recover?: typeof recoverManagedTaskRun
  storage?: Storage | undefined
}>(), { disabled: false })
const projectId = ref('')
let request = 0

watch([() => props.workspaceId, () => props.disabled], async ([workspaceId, disabled]) => {
  const current = ++request
  projectId.value = ''
  if (disabled) return
  try {
    const workspace = await (props.loadWorkspace ?? getCanonicalWorkspace)(workspaceId)
    if (request === current && props.workspaceId === workspaceId && !props.disabled && workspace.workspaceId === workspaceId) projectId.value = workspace.projectId
  } catch {
    if (request === current && props.workspaceId === workspaceId && !props.disabled) projectId.value = ''
  }
}, { immediate: true })

onBeforeUnmount(() => { request += 1 })
</script>

<template>
  <TaskComposer :project-id="projectId" :workspace-id="workspaceId" :disabled="disabled" :prepare="prepare" :start="start" :recover="recover" :storage="storage" />
</template>
