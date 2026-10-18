<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { RouterLink } from 'vue-router'

import { tryUseRuntimeSession } from '@/app/providers/runtime-session'
import {
  createPermissionModeIntent,
  getPermissionModeCommandStatus,
  getPermissionModeStatus,
  permissionModeRecoveryAddress,
  requestPermissionModeChange,
  restorePermissionModeIntent,
  type PermissionMode,
  type PermissionModeCommandStatus,
  type PermissionModeIntent,
  type PermissionModeStatus,
} from '@/entities/permission-mode'
import { translate, type LocaleKey } from '@/shared/i18n'

const props = defineProps<{
  workspaceId: string
  runtimeReady: boolean
  mutationAllowed?: boolean
  loadStatus?: typeof getPermissionModeStatus
  requestChange?: typeof requestPermissionModeChange
  readCommand?: typeof getPermissionModeCommandStatus
}>()

const modes: readonly PermissionMode[] = ['ask_always', 'risk_based', 'full_access']
const modeKeys: Record<PermissionMode, LocaleKey> = {
  ask_always: 'permissionMode.askAlways',
  risk_based: 'permissionMode.riskBased',
  full_access: 'permissionMode.fullAccess',
}
const runtimeSession = tryUseRuntimeSession()
const status = ref<PermissionModeStatus | null>(null)
const commandStatus = ref<PermissionModeCommandStatus | null>(null)
const activeIntent = ref<PermissionModeIntent | null>(null)
const loading = ref(false)
const submitting = ref(false)
const readingCommand = ref(false)
const unavailable = ref(false)
const readbackNeeded = ref(false)
const readbackUnavailable = ref(false)
const recoveryBlocked = ref(false)
let statusRequest = 0
let commandRequest = 0

const canMutate = computed(() => props.mutationAllowed ?? runtimeSession?.snapshot.value.canMutate === true)
const busy = computed(() => submitting.value || readingCommand.value || loading.value)
const blocked = computed(() => !props.runtimeReady || !canMutate.value || busy.value || activeIntent.value !== null || recoveryBlocked.value || status.value === null)

function recoveryKey(workspaceId: string): string {
  return `runne.permission-mode.intent.v1.${workspaceId}`
}

function restoreSavedIntent(workspaceId: string): void {
  activeIntent.value = null
  recoveryBlocked.value = false
  readbackNeeded.value = false
  try {
    const saved = localStorage.getItem(recoveryKey(workspaceId))
    if (saved === null) return
    if (saved.length > 1024) throw new Error('Invalid saved permission intent')
    const intent = restorePermissionModeIntent(JSON.parse(saved), workspaceId)
    if (intent === null) throw new Error('Invalid saved permission intent')
    activeIntent.value = intent
  }
  catch {
    recoveryBlocked.value = true
    readbackNeeded.value = true
  }
}

function saveIntentBeforePost(intent: PermissionModeIntent): boolean {
  try {
    const key = recoveryKey(intent.workspaceId)
    const existing = localStorage.getItem(key)
    if (existing !== null) {
      restoreSavedIntent(intent.workspaceId)
      return false
    }
    const address = JSON.stringify(permissionModeRecoveryAddress(intent))
    localStorage.setItem(key, address)
    if (localStorage.getItem(key) !== address) return false
    return true
  }
  catch {
    recoveryBlocked.value = true
    return false
  }
}

function removeCompletedIntent(intent: PermissionModeIntent): boolean {
  try {
    const key = recoveryKey(intent.workspaceId)
    const saved = localStorage.getItem(key)
    if (saved === null) return true
    const current = restorePermissionModeIntent(JSON.parse(saved), intent.workspaceId)
    if (current?.commandId !== intent.commandId) return false
    localStorage.removeItem(key)
    return true
  }
  catch {
    return false
  }
}

function modeLabel(mode: PermissionMode): string {
  return translate(modeKeys[mode])
}

function effectiveLabel(value: PermissionModeStatus['effective']): string {
  return value.state === 'ready'
    ? modeLabel(value.mode)
    : translate(`permissionMode.reason.${value.reason}`)
}

function modeDisabled(mode: PermissionMode): boolean {
  if (blocked.value || status.value === null || status.value.selectedMode !== mode) return blocked.value
  if (status.value.effective.state === 'notReady') return status.value.effective.reason !== 'native_containment'
  return status.value.expiresAtUnixMs === null || status.value.expiresAtUnixMs > Date.now()
}

async function refreshStatus(): Promise<boolean> {
  if (!props.runtimeReady) return false
  const request = ++statusRequest
  const workspaceId = props.workspaceId
  loading.value = true
  try {
    const result = await (props.loadStatus ?? getPermissionModeStatus)(workspaceId)
    if (request !== statusRequest || workspaceId !== props.workspaceId || !props.runtimeReady) return false
    status.value = result
    unavailable.value = false
    return true
  }
  catch {
    if (request === statusRequest) {
      status.value = null
      unavailable.value = true
    }
    return false
  }
  finally {
    if (request === statusRequest) loading.value = false
  }
}

async function readBack(): Promise<void> {
  const intent = activeIntent.value
  if (!props.runtimeReady || intent === null || intent.workspaceId !== props.workspaceId || readingCommand.value) return
  const request = ++commandRequest
  readingCommand.value = true
  readbackNeeded.value = false
  readbackUnavailable.value = false
  try {
    const result = await (props.readCommand ?? getPermissionModeCommandStatus)(intent)
    if (request !== commandRequest || activeIntent.value?.commandId !== intent.commandId || !props.runtimeReady) return
    commandStatus.value = result
    const statusLoaded = await refreshStatus()
    if (statusLoaded && result.state !== 'pending_native_confirmation' && result.state !== 'pending_reauthentication') {
      if (removeCompletedIntent(intent)) {
        activeIntent.value = null
        commandStatus.value = null
      }
      else recoveryBlocked.value = true
    }
  }
  catch (error) {
    if (request === commandRequest) {
      readbackNeeded.value = true
      readbackUnavailable.value = typeof error === 'object' && error !== null
        && 'code' in error && error.code === 'permission_command_unavailable'
    }
  }
  finally {
    if (request === commandRequest) readingCommand.value = false
  }
}

async function chooseMode(mode: PermissionMode): Promise<void> {
  const current = status.value
  if (modeDisabled(mode) || current === null) return
  const intent = createPermissionModeIntent(props.workspaceId, mode, current.authorizationRevision)
  if (!saveIntentBeforePost(intent)) {
    if (activeIntent.value !== null) await readBack()
    else recoveryBlocked.value = true
    return
  }
  activeIntent.value = intent
  commandStatus.value = null
  submitting.value = true
  try {
    await (props.requestChange ?? requestPermissionModeChange)(intent)
    await readBack()
  }
  catch {
    // The send may have reached the runtime. Keep this exact ID and only read it back.
    await readBack()
  }
  finally {
    submitting.value = false
  }
}

watch(() => [props.workspaceId, props.runtimeReady] as const, async ([workspaceId, ready], previous) => {
  if (previous !== undefined && previous[0] !== workspaceId) {
    statusRequest += 1
    commandRequest += 1
    status.value = null
    unavailable.value = true
    loading.value = false
    readingCommand.value = false
    readbackNeeded.value = false
    restoreSavedIntent(workspaceId)
    commandStatus.value = null
  }
  else if (previous === undefined) restoreSavedIntent(workspaceId)
  if (!ready) {
    statusRequest += 1
    commandRequest += 1
    status.value = null
    unavailable.value = true
    loading.value = false
    readingCommand.value = false
    return
  }
  await refreshStatus()
  if (activeIntent.value?.workspaceId === workspaceId) await readBack()
}, { immediate: true })

onBeforeUnmount(() => {
  statusRequest += 1
  commandRequest += 1
})
</script>

<template>
  <section class="workspace-permission-mode" aria-labelledby="permission-mode-title">
    <h2 id="permission-mode-title">{{ translate('permissionMode.title') }}</h2>
    <p v-if="!runtimeReady || unavailable" role="status">{{ translate('permissionMode.unavailable') }}</p>
    <p v-else-if="loading && status === null" role="status">{{ translate('permissionMode.loading') }}</p>
    <template v-if="status !== null">
      <dl>
        <dt>{{ translate('permissionMode.selected') }}</dt><dd>{{ modeLabel(status.selectedMode) }}</dd>
        <dt>{{ translate('permissionMode.effective') }}</dt><dd>{{ effectiveLabel(status.effective) }}</dd>
        <dt>{{ translate('permissionMode.revision') }}</dt><dd>{{ status.authorizationRevision }}</dd>
        <dt>{{ translate('permissionMode.containment') }}</dt><dd>{{ status.containment ?? translate('permissionMode.unavailableValue') }}</dd>
        <dt>{{ translate('permissionMode.network') }}</dt><dd>{{ status.networkState }}</dd>
        <dt>{{ translate('permissionMode.expiry') }}</dt><dd>{{ status.expiresAtUnixMs ?? translate('permissionMode.noExpiry') }}</dd>
        <dt>{{ translate('permissionMode.pendingApprovals') }}</dt>
        <dd>
          <RouterLink to="/approvals">{{ status.pendingApprovals }}</RouterLink>
        </dd>
      </dl>
      <fieldset :disabled="blocked">
        <legend>{{ translate('permissionMode.choose') }}</legend>
        <button
          v-for="mode in modes"
          :key="mode"
          type="button"
          :aria-pressed="status.selectedMode === mode"
          :disabled="modeDisabled(mode)"
          @click="chooseMode(mode)"
        >{{ modeLabel(mode) }}</button>
      </fieldset>
    </template>
    <p v-if="activeIntent !== null" role="status">
      <template v-if="readbackNeeded">{{ translate(readbackUnavailable ? 'permissionMode.readbackUnavailable' : 'permissionMode.readbackUnknown') }}</template>
      <template v-else-if="commandStatus === null || busy">{{ translate('permissionMode.checking') }}</template>
      <template v-else-if="commandStatus.state === 'pending_native_confirmation' || commandStatus.state === 'pending_reauthentication'">
        {{ translate('permissionMode.pendingNative', { expiry: commandStatus.expiresAtUnixMs }) }}
      </template>
      <template v-else>{{ translate('permissionMode.commandResult', { state: commandStatus.state }) }}</template>
    </p>
    <p v-if="recoveryBlocked" role="alert">{{ translate('permissionMode.recoveryBlocked') }}</p>
    <p v-else-if="runtimeReady && !canMutate" role="status">{{ translate('permissionMode.readOnly') }}</p>
    <button v-if="activeIntent !== null" type="button" :disabled="!runtimeReady || busy" @click="readBack">
      {{ translate('permissionMode.checkStatus') }}
    </button>
    <p>{{ translate('permissionMode.nativeBoundary') }}</p>
  </section>
</template>
