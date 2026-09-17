<script setup lang="ts">
import { Archive, MoreHorizontal, Pencil, Trash2 } from 'lucide-vue-next'
import { nextTick, onBeforeUnmount, onMounted, ref, useId, watch } from 'vue'
import { translate } from '@/shared/i18n'

const props = defineProps<{ archived: boolean; disabled: boolean }>()
const emit = defineEmits<{ action: [operation: 'archive' | 'delete']; rename: [] }>()
const id = useId()
const panel = ref<HTMLElement>()
const trigger = ref<HTMLButtonElement>()
defineExpose({ focus: () => trigger.value?.focus() })
const expanded = ref(false)
const position = ref({ top: '0px', right: '12px' })

function place() {
  const bounds = trigger.value?.getBoundingClientRect()
  if (bounds) position.value = { top: `${bounds.bottom + 6}px`, right: `${Math.max(12, window.innerWidth - bounds.right)}px` }
}

async function toggle() {
  if (props.disabled) return
  if (expanded.value) { close(); return }
  place()
  expanded.value = true
  await nextTick()
  panel.value?.querySelector<HTMLButtonElement>('button:not(:disabled)')?.focus()
}
function close(focus = true) {
  expanded.value = false
  if (focus) trigger.value?.focus()
}
function outside(event: Event) {
  const target = event.target as Node
  if (!panel.value?.contains(target) && !trigger.value?.contains(target)) close(false)
}
function key(event: KeyboardEvent) {
  if (event.key === 'Escape' && expanded.value) {
    event.preventDefault()
    event.stopPropagation()
    close()
  }
}
onMounted(() => {
  document.addEventListener('pointerdown', outside)
  document.addEventListener('focusin', outside)
  document.addEventListener('keydown', key, true)
})
onBeforeUnmount(() => {
  document.removeEventListener('pointerdown', outside)
  document.removeEventListener('focusin', outside)
  document.removeEventListener('keydown', key, true)
})
watch(() => props.disabled, disabled => { if (disabled && expanded.value) close(false) })

function select(operation: 'archive' | 'delete') {
  close()
  trigger.value?.focus()
  emit('action', operation)
}
</script>

<template>
  <div class="project-menu">
    <button
      ref="trigger"
      type="button"
      class="project-menu__trigger"
      :aria-expanded="expanded"
      :aria-controls="id"
      aria-haspopup="menu"
      :aria-label="translate('projects.manageProject')"
      :disabled="disabled"
      @click="toggle"
    >
      <MoreHorizontal
        :size="18"
        aria-hidden="true"
      />
    </button>
    <div
      v-if="expanded"
      :id="id"
      ref="panel"
      :style="position"
      class="project-menu__panel"
      role="menu"
      :aria-label="translate('projects.manageProject')"
    >
      <button
        v-if="!archived"
        type="button"
        role="menuitem"
        :disabled="disabled"
        @click="close(); emit('rename')"
      >
        <Pencil
          :size="16"
          aria-hidden="true"
        />{{ translate('projects.rename') }}
      </button>
      <button
        v-if="!archived"
        type="button"
        role="menuitem"
        :disabled="disabled"
        :aria-label="translate('projectDetails.archiveProject')"
        @click="select('archive')"
      >
        <Archive
          :size="16"
          aria-hidden="true"
        />{{ translate('projectDetails.archiveProject') }}
      </button>
      <button
        type="button"
        class="project-menu__delete"
        role="menuitem"
        :disabled="disabled"
        :aria-label="translate('projectDetails.deleteProject')"
        @click="select('delete')"
      >
        <Trash2
          :size="16"
          aria-hidden="true"
        />{{ translate('projectDetails.deleteProject') }}
      </button>
    </div>
  </div>
</template>

<style scoped>
.project-menu { position: relative; }
.project-menu__trigger {
  display: grid; place-items: center; width: 32px; height: 32px;
  background: transparent; color: var(--runne-text-secondary);
  border: 1px solid transparent; border-radius: 6px; cursor: pointer;
}
.project-menu__trigger:hover, .project-menu__trigger[aria-expanded="true"] {
  background: var(--runne-surface-raised); color: var(--runne-text-primary);
}
.project-menu__panel {
  position: fixed; inset: auto; z-index: 100;
  margin: 0; padding: 4px; min-width: 200px; max-width: calc(100vw - 24px);
  background: var(--runne-surface-raised, #20262d); color: var(--runne-text-primary);
  border: 1px solid var(--runne-border); border-radius: 8px;
  box-shadow: 0 8px 24px #0003;
}
.project-menu__panel button {
  display: flex; align-items: center; gap: 8px; width: 100%; min-height: 32px;
  padding: 6px 8px; border: 0; border-radius: 4px; background: transparent;
  color: inherit; font: inherit; font-size: 13px; text-align: left; cursor: pointer;
}
.project-menu__panel button:hover { background: var(--runne-border); }
.project-menu__panel .project-menu__delete { color: var(--runne-error-coral); }
.project-menu__panel button:disabled { opacity: .45; cursor: default; }
button:focus-visible { outline: 2px solid var(--runne-accent); outline-offset: -2px; }
</style>
