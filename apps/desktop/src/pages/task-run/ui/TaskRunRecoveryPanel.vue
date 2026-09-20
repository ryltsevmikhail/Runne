<script setup lang="ts">
import { GcAlert } from '@runne/product/shared/ui'
import { computed } from 'vue'

import type { TaskRunRecovery } from '@/entities/task-run'
import { translate, type LocaleKey } from '@/shared/i18n'

const props = defineProps<{
  readonly recovery: TaskRunRecovery
  readonly projectionRevision: number
  readonly streamVersion: number
  readonly lastCommittedAt: number | null
}>()

// Единицы committedAt не зафиксированы TS-контрактом (микросекунды известны
// только по crates/runne-domain/src/timestamp.rs), поэтому значение не
// рендерится: lastCommittedAt используется лишь как сигнал наличия
// подтверждённых событий.
// Отдельный читаемый текст на каждое не-live recovery: пользователь должен
// различать потерю связи, требуемую ревалидацию и терминальные отказы.
// Хранится ключ локали, translate() вызывается внутри computed — иначе текст
// зафиксируется на локали момента setup и перестанет реагировать на её смену.
const recoveryAlerts: Record<Exclude<TaskRunRecovery, 'live'>, { level: 'warning' | 'error', key: LocaleKey }> = {
  reconnecting: { level: 'warning', key: 'taskRun.connectionLost' },
  resync_required: { level: 'warning', key: 'taskRun.replayNeedsRevalidation' },
  fatal: { level: 'error', key: 'taskRun.replayFailedPermanently' },
  revoked: { level: 'error', key: 'taskRun.accessRevoked' },
  incompatible: { level: 'error', key: 'taskRun.runtimeIncompatible' },
}
const recoveryAlert = computed(() => {
  if (props.recovery === 'live') return null
  const alert = recoveryAlerts[props.recovery]
  return { level: alert.level, text: translate(alert.key) }
})
const staleText = computed(() => {
  const event = props.lastCommittedAt === null ? ` · ${translate('taskRun.noConfirmedEvents')}` : ''
  return translate('taskRun.staleSnapshot', { revision: props.projectionRevision, stream: props.streamVersion, event })
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
