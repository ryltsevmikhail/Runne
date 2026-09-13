<script setup lang="ts">
import { isTauri } from '@tauri-apps/api/core'
import { GcDialog } from '@runne/product/shared/ui'
import { nextTick, onBeforeUnmount, ref } from 'vue'
import { getCanonicalProject, renameCanonicalProject, executeCanonicalProjectDestructiveAction, type CanonicalProject } from '@/entities/project'
import { translate } from '@/shared/i18n'
import ProjectActionsMenu from './ProjectActionsMenu.vue'
import RenameProjectDialog from './RenameProjectDialog.vue'

const props = defineProps<{ project: CanonicalProject; disabled: boolean }>()
const emit = defineEmits<{ removed: [] }>()
const menu = ref<InstanceType<typeof ProjectActionsMenu>>()
const renaming = ref(false)
let renameVersion = props.project.version
function beginRename() { renameVersion = props.project.version; renaming.value = true }
const pending = ref(false)
const error = ref(false)
const confirming = ref<'archive' | 'delete' | null>(null)
let alive = true
onBeforeUnmount(() => { alive = false })
async function close() { renaming.value = false; await nextTick(); menu.value?.focus() }
async function mutate(operation: 'rename' | 'archive' | 'delete', name?: string) {
  if (pending.value || props.disabled) throw new Error('Unavailable')
  const id = props.project.projectId
  pending.value = true
  error.value = false
  try {
    const { project } = await getCanonicalProject(id)
    if (!alive || props.disabled || props.project.projectId !== id) throw new Error('Unavailable')
    if (operation === 'rename') {
      if (project.version !== renameVersion) throw new Error('Project changed')
      await renameCanonicalProject(id, renameVersion, name!)
    }
    else {
      const outcome = await executeCanonicalProjectDestructiveAction(id, project.version, operation)
      if (alive && outcome === 'completed') emit('removed')
    }
  }
  finally { pending.value = false }
}
async function runDestructive(operation: 'archive' | 'delete') {
  try { await mutate(operation) }
  catch { if (alive) error.value = true }
}
async function destructive(operation: 'archive' | 'delete') {
  if (!isTauri()) {
    confirming.value = operation
    return
  }
  await runDestructive(operation)
}
async function confirmDestructive() {
  const operation = confirming.value
  if (operation === null) return
  confirming.value = null
  await runDestructive(operation)
}
async function cancelDestructive() {
  confirming.value = null
  await nextTick()
  menu.value?.focus()
}
</script>

<template>
  <ProjectActionsMenu ref="menu" :archived="project.archived" :disabled="disabled || pending"
    @action="destructive" @rename="beginRename" />
  <GcDialog
    v-if="confirming !== null"
    :open="true"
    :title="translate(confirming === 'delete' ? 'projects.confirmDeleteTitle' : 'projects.confirmArchiveTitle')"
    :description="translate(confirming === 'delete' ? 'projects.confirmDeleteMessage' : 'projects.confirmArchiveMessage', { name: project.displayName })"
    :confirm-label="translate('projects.confirm')"
    :cancel-label="translate('projects.cancel')"
    :danger="confirming === 'delete'"
    @confirm="confirmDestructive"
    @cancel="cancelDestructive"
  />
  <RenameProjectDialog v-if="renaming" :name="project.displayName"
    :save="name => mutate('rename', name)" @close="close" />
  <p v-if="error" class="project-management-error" role="alert">{{ translate('projectDetails.destructiveActionFailed') }}</p>
</template>

<style scoped>
.project-management-error { grid-column: 1 / -1; margin: 4px 6px; font-size: 11px; color: var(--runne-error-coral); }
</style>
