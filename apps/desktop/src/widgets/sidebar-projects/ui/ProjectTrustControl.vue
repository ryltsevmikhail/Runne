<script setup lang="ts">
import { onBeforeUnmount, ref, watch } from 'vue'
import { getProjectTrustControl, markProjectTrustChanged, projectTrustRevision, requestProjectTrustControl, type ProjectTrustControlSnapshot } from '@/entities/project'
import { translate } from '@/shared/i18n'

const props = defineProps<{ projectId: string; workspaceId: string; disabled: boolean }>()
const snapshot = ref<ProjectTrustControlSnapshot>()
const loading = ref(false)
const busy = ref(false)
const failed = ref(false)
let alive = true
let generation = 0
const observedTrustRevision = ref(projectTrustRevision(props.projectId))
onBeforeUnmount(() => { alive = false; generation += 1 })
watch(() => [props.projectId, props.workspaceId, props.disabled] as const, () => {
  observedTrustRevision.value = projectTrustRevision(props.projectId)
  generation += 1
  snapshot.value = undefined
  failed.value = false
  loading.value = false
  if (!props.disabled) void refresh()
}, { immediate: true })
watch(() => projectTrustRevision(props.projectId), revision => {
  if (revision === observedTrustRevision.value) return
  observedTrustRevision.value = revision
  if (!props.disabled) void refresh()
})

function markTrustReadbackChanged(projectId: string) {
  observedTrustRevision.value = projectTrustRevision(projectId) + 1
  markProjectTrustChanged(projectId)
}

async function refresh(projectId = props.projectId, workspaceId = props.workspaceId): Promise<boolean> {
  const requestGeneration = ++generation
  loading.value = true
  failed.value = false
  snapshot.value = undefined
  try {
    const value = await getProjectTrustControl(projectId, workspaceId)
    if (alive && requestGeneration === generation && !props.disabled
      && projectId === props.projectId && workspaceId === props.workspaceId) {
      snapshot.value = value
      return true
    }
    return false
  }
  catch { if (alive && requestGeneration === generation) failed.value = true; return false }
  finally { if (alive && requestGeneration === generation) loading.value = false }
}

async function changeTrust() {
  const observed = snapshot.value
  if (busy.value || props.disabled || !observed || observed.status === 'managed'
    || observed.provenance === 'managed' || observed.managedDenyMask !== 0
    || observed.projectId !== props.projectId || observed.workspaceId !== props.workspaceId) return
  busy.value = true
  failed.value = false
  const requestGeneration = generation
  const projectId = props.projectId
  const workspaceId = props.workspaceId
  try {
    const action = observed.status === 'trusted' ? 'revoke_project' : 'confirm_project'
    if (action === 'confirm_project' && observed.rootAdmissionVersion === null) {
      failed.value = true
      return
    }
    const result = await requestProjectTrustControl(projectId, workspaceId, action)
    if (result.outcome === 'updated' && result.snapshot) {
      if (alive && requestGeneration === generation) snapshot.value = result.snapshot
      if (alive && requestGeneration === generation) markTrustReadbackChanged(projectId)
      else markProjectTrustChanged(projectId)
    }
  }
  catch {
    // An unknown commit result always reads again. It never retries the decision.
    if (alive && requestGeneration === generation) markTrustReadbackChanged(projectId)
    else markProjectTrustChanged(projectId)
    try {
      const readback = await getProjectTrustControl(projectId, workspaceId)
      if (alive && requestGeneration === generation && !props.disabled
        && projectId === props.projectId && workspaceId === props.workspaceId) {
        snapshot.value = readback
        failed.value = true
      }
    } catch {
      if (alive && requestGeneration === generation) failed.value = true
    }
  }
  finally { if (alive) busy.value = false }
}

const statusText = () => snapshot.value?.provenance === 'managed' || snapshot.value?.managedDenyMask !== 0
  ? translate('projectTrust.managed')
  : snapshot.value?.status === 'trusted'
  ? translate('projectTrust.trusted')
  : snapshot.value?.status === 'managed'
    ? translate('projectTrust.managed')
    : translate('projectTrust.untrusted')
</script>

<template>
  <div class="trust-control">
    <span v-if="loading && !snapshot" class="trust-status">{{ translate('projectTrust.loading') }}</span>
    <template v-else-if="snapshot">
      <span class="trust-status" :data-status="snapshot.status">{{ statusText() }}</span>
      <button v-if="snapshot.status !== 'managed' && snapshot.provenance !== 'managed' && snapshot.managedDenyMask === 0" type="button" class="trust-action"
        :disabled="disabled || busy || (snapshot.status === 'untrusted' && snapshot.rootAdmissionVersion === null)"
        @click="changeTrust">
        {{ translate(snapshot.status === 'trusted' ? 'projectTrust.revoke' : 'projectTrust.confirm') }}
      </button>
      <span class="trust-scope">{{ translate('projectTrust.scope') }}</span>
    </template>
    <span v-if="snapshot?.status === 'untrusted' && snapshot.rootAdmissionVersion === null" class="trust-scope">{{ translate('projectTrust.rootUnavailable') }}</span>
    <button v-if="failed" type="button" class="trust-error" @click="() => refresh()">
      {{ translate('projectTrust.changed') }} {{ translate('projectTrust.refresh') }}
    </button>
    <span v-else-if="!snapshot && !loading" class="trust-error">{{ translate('projectTrust.unavailable') }}</span>
  </div>
</template>

<style scoped>
.trust-control { display: grid; gap: 3px; margin: 4px 4px 6px 24px; font-size: 10px; }
.trust-status { color: var(--runne-text-secondary); }
.trust-status[data-status="trusted"] { color: var(--runne-success, var(--runne-text-primary)); }
.trust-action, .trust-error { width: fit-content; padding: 2px 5px; border: 0; background: transparent; color: var(--runne-accent); font: inherit; text-align: left; cursor: pointer; }
.trust-scope, .trust-error { color: var(--runne-text-secondary); }
button:disabled { opacity: .5; cursor: default; }
</style>
