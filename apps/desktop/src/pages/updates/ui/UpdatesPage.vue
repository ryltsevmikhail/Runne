<script setup lang="ts">
import { isTauri } from '@tauri-apps/api/core'
import { onMounted, ref } from 'vue'

import type { SettingsPageAdapter } from '@/pages/settings'
import SettingsStatePage from '@/pages/settings/ui/SettingsStatePage.vue'
import {
  checkUpdate as nativeCheckUpdate,
  downloadUpdate as nativeDownloadUpdate,
  getUpdateStatus,
  prepareUpdateInstall as nativePrepareUpdateInstall,
  type UpdateStatusSnapshot,
} from '@/shared/api/platform/updates'
import { translate } from '@/shared/i18n'

type LoadUpdateStatus = () => Promise<UpdateStatusSnapshot>
type UpdateAction = () => Promise<UpdateStatusSnapshot>
type PrepareUpdateInstall = (confirmActiveTaskRuns: boolean) => Promise<UpdateStatusSnapshot>

const props = defineProps<{
  readonly adapter?: SettingsPageAdapter
  readonly loadUpdateStatus?: LoadUpdateStatus
  readonly checkUpdate?: UpdateAction
  readonly downloadUpdate?: UpdateAction
  readonly prepareUpdateInstall?: PrepareUpdateInstall
}>()

const status = ref<UpdateStatusSnapshot | null>(null)
const loading = ref(true)
const failed = ref(false)
const action = ref<'check' | 'download' | 'prepare' | null>(null)
const actionFailed = ref(false)
const confirmActiveTaskRuns = ref(false)

async function loadStatus() {
  try {
    status.value = await (props.loadUpdateStatus ?? (async () => {
      if (!isTauri()) throw new Error('native update status unavailable')
      return getUpdateStatus()
    }))()
  }
  catch {
    failed.value = true
  }
  finally {
    loading.value = false
  }
}

async function runAction(kind: 'check' | 'download' | 'prepare') {
  action.value = kind
  actionFailed.value = false
  try {
    const prepare = props.prepareUpdateInstall
      ?? ((confirm: boolean) => nativePrepareUpdateInstall(confirm))
    const next = kind === 'check'
      ? await (props.checkUpdate ?? nativeCheckUpdate)()
      : kind === 'download'
        ? await (props.downloadUpdate ?? nativeDownloadUpdate)()
        : await prepare(confirmActiveTaskRuns.value)
    status.value = next
  }
  catch {
    actionFailed.value = true
  }
  finally {
    action.value = null
  }
}

onMounted(() => {
  if (props.adapter === undefined) void loadStatus()
})
</script>

<template>
  <SettingsStatePage
    v-if="props.adapter !== undefined"
    title="Updates"
    title-key="settings.updates"
    :adapter="props.adapter"
  />
  <section v-else-if="loading" aria-live="polite">
    <h1>{{ translate('updates.loading') }}</h1>
  </section>
  <section v-else-if="failed || status === null" role="alert">
    <h1>{{ translate('updates.unavailable') }}</h1>
    <p>{{ translate('updates.unavailableMessage') }}</p>
  </section>
  <section v-else aria-labelledby="updates-title">
    <h1 id="updates-title">{{ translate('settings.updates') }}</h1>
    <dl>
      <div><dt>{{ translate('updates.currentVersion') }}</dt><dd>{{ status.currentVersion }}</dd></div>
      <div><dt>{{ translate('updates.state') }}</dt><dd>{{ status.state }}</dd></div>
      <div v-if="status.availableVersion !== null"><dt>{{ translate('updates.availableVersion') }}</dt><dd>{{ status.availableVersion }}</dd></div>
      <div v-if="status.artifactSha256 !== null"><dt>{{ translate('updates.artifactDigest') }}</dt><dd>{{ status.artifactSha256 }}</dd></div>
      <div v-if="status.reason !== null"><dt>{{ translate('updates.reason') }}</dt><dd>{{ status.reason }}</dd></div>
    </dl>
    <p v-if="actionFailed" role="alert">{{ translate('updates.actionFailed') }}</p>
    <p v-if="status.state === 'restart_required'" role="status">{{ translate('updates.restartRequired') }}</p>
    <button v-if="status.state === 'unavailable'" type="button" :disabled="action !== null" @click="runAction('check')">
      {{ action === 'check' ? translate('updates.working') : translate('updates.check') }}
    </button>
    <button v-else-if="status.state === 'available'" type="button" :disabled="action !== null" @click="runAction('download')">
      {{ action === 'download' ? translate('updates.working') : translate('updates.download') }}
    </button>
    <div v-else-if="status.state === 'staged'" :aria-label="translate('updates.installationConfirmation')">
      <label>
        <input v-model="confirmActiveTaskRuns" type="checkbox">
        {{ translate('updates.confirmActiveTaskRuns') }}
      </label>
      <button type="button" :disabled="!confirmActiveTaskRuns || action !== null" @click="runAction('prepare')">
        {{ action === 'prepare' ? translate('updates.working') : translate('updates.prepareRestart') }}
      </button>
    </div>
  </section>
</template>
