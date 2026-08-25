<script setup lang="ts">
import { GcAlert } from '@runne/product/shared/ui'
import { isTauri } from '@tauri-apps/api/core'
import { computed, onMounted, ref } from 'vue'

import { loadShortcuts, saveShortcuts, type ShortcutBindings } from '@/shared/api/platform/shortcuts'
import { isShortcutBindings } from '@/shared/api/platform/shortcuts'
import { unavailableSettingsPageAdapter, type SettingsPageAdapter } from '@/pages/settings'
import SettingsStatePage from '@/pages/settings/ui/SettingsStatePage.vue'
import { translate } from '@/shared/i18n'

const DEFAULT_BINDINGS: ShortcutBindings = {
  commandPalette: 'Ctrl+Shift+P',
  openProject: 'Ctrl+O',
}

const props = defineProps<{
  readonly adapter?: SettingsPageAdapter
  readonly loadBindings?: () => Promise<ShortcutBindings>
  readonly saveBindings?: (bindings: ShortcutBindings) => Promise<ShortcutBindings>
}>()

const bindings = ref<ShortcutBindings>({ ...DEFAULT_BINDINGS })
const loading = ref(true)
const saving = ref(false)
const unavailable = ref(false)
const saveFailed = ref(false)
const saved = ref(false)

const conflict = computed(() => bindings.value.commandPalette === bindings.value.openProject)

async function readBindings() {
  try {
    bindings.value = await (props.loadBindings ?? defaultLoad)()
    unavailable.value = false
  }
  catch {
    unavailable.value = true
  }
  finally {
    loading.value = false
  }
}

async function save() {
  if (conflict.value || !isShortcutBindings(bindings.value)) return
  saving.value = true
  saveFailed.value = false
  saved.value = false
  try {
    bindings.value = await (props.saveBindings ?? defaultSave)(bindings.value)
    saved.value = true
  }
  catch {
    saveFailed.value = true
  }
  finally {
    saving.value = false
  }
}

async function recover() {
  loading.value = true
  await readBindings()
}

async function defaultLoad(): Promise<ShortcutBindings> {
  return isTauri() ? loadShortcuts() : { ...DEFAULT_BINDINGS }
}

async function defaultSave(value: ShortcutBindings): Promise<ShortcutBindings> {
  return isTauri() ? saveShortcuts(value) : value
}

onMounted(() => {
  if (props.adapter === undefined) void readBindings()
})
</script>

<template>
  <SettingsStatePage
    v-if="props.adapter !== undefined"
    :title="translate('settings.shortcuts')"
    title-key="settings.shortcuts"
    :adapter="props.adapter ?? unavailableSettingsPageAdapter(translate('settings.shortcuts'))"
  />
  <section
    v-else
    aria-labelledby="shortcuts-title"
  >
    <header class="page-header">
      <div>
        <h1 id="shortcuts-title">{{ translate('settings.shortcuts') }}</h1>
        <p>{{ translate('shortcuts.description') }}</p>
      </div>
    </header>
    <div v-if="loading" class="empty-state" aria-live="polite">
      <h2>{{ translate('shortcuts.loading') }}</h2>
    </div>
    <GcAlert v-else-if="unavailable" level="error" :title="translate('shortcuts.unavailable')" role="alert">
      {{ translate('shortcuts.unavailableMessage') }}
      <button type="button" @click="recover">{{ translate('shortcuts.retry') }}</button>
    </GcAlert>
    <form v-else class="shortcut-form" @submit.prevent="save">
      <label>
        <span>{{ translate('shortcuts.commandPalette') }}</span>
        <input v-model="bindings.commandPalette" name="commandPalette" autocomplete="off">
      </label>
      <label>
        <span>{{ translate('shortcuts.openProject') }}</span>
        <input v-model="bindings.openProject" name="openProject" autocomplete="off">
      </label>
      <p v-if="conflict" role="alert">{{ translate('shortcuts.conflict') }}</p>
      <GcAlert v-if="saveFailed" level="error" :title="translate('shortcuts.saveFailed')" role="alert">
        {{ translate('shortcuts.saveFailedMessage') }}
      </GcAlert>
      <p v-if="saved" role="status">{{ translate('shortcuts.saved') }}</p>
      <button type="submit" :disabled="saving || conflict">{{ translate('shortcuts.save') }}</button>
    </form>
  </section>
</template>
