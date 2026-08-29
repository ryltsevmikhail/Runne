<script setup lang="ts">
import { File, Folder } from 'lucide-vue-next'
import { ref } from 'vue'

import type { WorkspaceFileEntry } from '@/entities/file-tree'
import { translate } from '@/shared/i18n'

const props = withDefaults(defineProps<{
  entries: readonly WorkspaceFileEntry[]
  loading: boolean
  error: boolean
  disabled?: boolean
  openFile?: (path: string) => Promise<void>
}>(), { disabled: false })

const openingPath = ref<string | null>(null)
const openError = ref(false)

async function openEntry(path: string) {
  if (props.disabled || props.openFile === undefined) return
  openingPath.value = path
  openError.value = false
  try {
    await props.openFile(path)
  }
  catch {
    openError.value = true
  }
  finally {
    openingPath.value = null
  }
}
</script>

<template>
  <div
    class="file-explorer"
    :aria-label="translate('files.workspaceFiles')"
  >
    <p
      v-if="loading"
      class="file-explorer__status"
      aria-live="polite"
    >
      {{ translate('files.loading') }}
    </p>
    <p
      v-else-if="error"
      class="file-explorer__status"
      role="alert"
    >
      {{ translate('files.unavailable') }}
    </p>
    <p
      v-else-if="entries.length === 0"
      class="file-explorer__status"
    >
      {{ translate('files.empty') }}
    </p>
    <p
      v-if="openError"
      class="file-explorer__status"
      role="alert"
    >
      {{ translate('files.editorFailed') }}
    </p>
    <ul
      v-else
      class="file-explorer__list"
    >
      <li
        v-for="entry in entries"
        :key="entry.path"
        class="file-explorer__entry"
      >
        <span class="file-explorer__icon">
          <Folder
            v-if="entry.kind === 'directory'"
            :size="14"
            aria-hidden="true"
          />
          <File
            v-else
            :size="14"
            aria-hidden="true"
          />
        </span>
        <span class="file-explorer__path">{{ entry.path }}</span>
        <button
          v-if="entry.kind === 'file'"
          class="file-explorer__action"
          type="button"
          :disabled="disabled || openFile === undefined || openingPath === entry.path"
          :aria-label="translate('files.openInEditor', { path: entry.path })"
          @click="openEntry(entry.path)"
        >
          {{ openingPath === entry.path ? translate('files.opening') : translate('files.open') }}
        </button>
      </li>
    </ul>
  </div>
</template>
