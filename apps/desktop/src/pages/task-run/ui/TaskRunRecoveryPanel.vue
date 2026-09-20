<script setup lang="ts">
import { GcAlert } from '@runne/product/shared/ui'
import { computed } from 'vue'

import type { TaskRunRecovery } from '@/entities/task-run'

const props = defineProps<{
  readonly recovery: TaskRunRecovery
  readonly projectionRevision: number
  readonly streamVersion: number
  readonly lastCommittedAt: number | null
}>()

// Отдельный читаемый текст на каждое не-live recovery: пользователь должен
// различать потерю связи, требуемую ревалидацию и терминальные отказы.
const recoveryAlerts: Record<Exclude<TaskRunRecovery, 'live'>, { level: 'warning' | 'error', text: string }> = {
  reconnecting: { level: 'warning', text: 'Connection to the task stream was lost.' },
  resync_required: { level: 'warning', text: 'Replay recovery needs revalidation.' },
  fatal: { level: 'error', text: 'Replay recovery failed permanently.' },
  revoked: { level: 'error', text: 'Access to this task run was revoked.' },
  incompatible: { level: 'error', text: 'Runtime is incompatible with this task run.' },
}
const recoveryAlert = computed(() => props.recovery === 'live' ? null : recoveryAlerts[props.recovery])
const staleText = computed(() => {
  const event = props.lastCommittedAt === null ? 'no confirmed events' : `event at ${props.lastCommittedAt}`
  return `Last confirmed snapshot: revision ${props.projectionRevision} · stream ${props.streamVersion} · ${event} — data may be outdated`
})
</script>

<template>
  <!-- Чисто презентационная панель: ни при одном recovery не рендерит кнопку,
       восстановление подписки остаётся за watch [taskRunId, runtimeStatus]. -->
  <template v-if="recoveryAlert !== null">
    <div v-if="recoveryAlert.level === 'error'" role="alert">
      <GcAlert :level="recoveryAlert.level" :title="recoveryAlert.text" />
    </div>
    <GcAlert v-else :level="recoveryAlert.level" :title="recoveryAlert.text" />
    <p role="status">{{ staleText }}</p>
  </template>
</template>
