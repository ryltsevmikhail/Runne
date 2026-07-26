<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import type { CommandItem } from './GcCommandPalette.types'

const props = defineProps<{
  open: boolean
  items: CommandItem[]
}>()

const emit = defineEmits<{
  select: [id: string]
  close: []
  'update:open': [value: boolean]
}>()

const search = ref('')
const activeIndex = ref(0)

const filtered = computed(() => {
  if (!search.value) return props.items
  const q = search.value.toLowerCase()
  return props.items.filter(i => i.label.toLowerCase().includes(q))
})

watch(filtered, (items) => {
  activeIndex.value = Math.min(activeIndex.value, Math.max(items.length - 1, 0))
})

function selectItem(id: string) {
  emit('select', id)
  emit('close')
}

function onKeydown(e: KeyboardEvent) {
  if (e.key === 'ArrowDown') { activeIndex.value = Math.min(activeIndex.value + 1, filtered.value.length - 1); e.preventDefault() }
  if (e.key === 'ArrowUp') { activeIndex.value = Math.max(activeIndex.value - 1, 0); e.preventDefault() }
  if (e.key === 'Enter') { const item = filtered.value[activeIndex.value]; if (item) { selectItem(item.id) } }
  if (e.key === 'Escape') { emit('close') }
}
</script>

<template>
  <Teleport to="body">
    <div v-if="open" class="gc-palette-overlay" @click="emit('close')">
      <div class="gc-palette" role="dialog" aria-label="Command palette" @click.stop @keydown="onKeydown">
        <input
          v-model="search"
          class="gc-palette-search"
          placeholder="Type a command or search..."
          aria-label="Search commands"
          autofocus
        />
        <div class="gc-palette-results">
          <button
            v-for="(item, i) in filtered"
            :key="item.id"
            :class="['gc-palette-item', { 'gc-palette-item--active': i === activeIndex }]"
            type="button"
            @click="selectItem(item.id)"
            @mouseenter="activeIndex = i"
          >
            <span class="gc-palette-label">{{ item.label }}</span>
            <kbd v-if="item.shortcut" class="gc-palette-shortcut">{{ item.shortcut }}</kbd>
          </button>
          <div v-if="filtered.length === 0" class="gc-palette-empty">No results</div>
        </div>
      </div>
    </div>
  </Teleport>
</template>

<style scoped>
.gc-palette-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.5);
  backdrop-filter: blur(4px);
  z-index: 200;
  display: flex;
  justify-content: center;
  padding-top: 15vh;
}

.gc-palette {
  width: 560px;
  max-height: 400px;
  background: var(--gocode-surface-raised);
  border: 1px solid var(--gocode-border);
  border-radius: var(--gocode-radius-xl);
  overflow: hidden;
  display: flex;
  flex-direction: column;
}

.gc-palette-search {
  padding: var(--gocode-space-lg);
  border: none;
  border-bottom: 1px solid var(--gocode-border);
  background: transparent;
  color: var(--gocode-text-primary);
  font-family: var(--gocode-font-ui);
  font-size: 16px;
  outline: none;
}

.gc-palette-results { overflow-y: auto; flex: 1; padding: var(--gocode-space-sm); }

.gc-palette-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: var(--gocode-space-sm) var(--gocode-space-md);
  border-radius: var(--gocode-radius-md);
  border: none;
  background: transparent;
  color: var(--gocode-text-primary);
  font-family: var(--gocode-font-ui);
  font-size: 14px;
  cursor: pointer;
  width: 100%;
  text-align: left;
}

.gc-palette-item--active { background: var(--gocode-surface); }

.gc-palette-shortcut {
  font-family: var(--gocode-font-mono);
  font-size: 12px;
  padding: 2px 6px;
  background: var(--gocode-surface);
  border-radius: var(--gocode-radius-sm);
  color: var(--gocode-ui-muted);
}

.gc-palette-empty { padding: var(--gocode-space-lg); text-align: center; color: var(--gocode-ui-muted); }
</style>
