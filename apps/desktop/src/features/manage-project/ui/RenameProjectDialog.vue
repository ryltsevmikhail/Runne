<script setup lang="ts">
import { GcButton } from '@runne/product/shared/ui'
import { computed, onMounted, ref } from 'vue'
import { translate } from '@/shared/i18n'

const props = defineProps<{ name: string; save: (name: string) => Promise<void> }>()
const emit = defineEmits<{ close: [] }>()
const dialog = ref<HTMLDialogElement>()
const name = ref(props.name)
const valid = computed(() => name.value.trim() !== props.name && name.value.trim().length > 0
  && new TextEncoder().encode(name.value.trim()).length <= 256 && !/[\p{Cc}\p{Cf}]/u.test(name.value))
const pending = ref(false)
const failed = ref(false)
onMounted(() => dialog.value?.showModal())

async function submit() {
  if (pending.value || !valid.value) return
  pending.value = true
  failed.value = false
  try {
    await props.save(name.value.trim())
    emit('close')
  }
  catch { failed.value = true }
  finally { pending.value = false }
}
</script>

<template>
  <dialog
    ref="dialog"
    class="rename-project"
    aria-labelledby="rename-title"
    @cancel.prevent="!pending && emit('close')"
  >
    <form @submit.prevent="submit">
      <h2 id="rename-title">
        {{ translate('projects.rename') }}
      </h2>
      <label for="project-name">{{ translate('projects.name') }}</label>
      <input
        id="project-name"
        v-model="name"
        autofocus
        maxlength="256"
        required
        :disabled="pending"
        @focus="($event.target as HTMLInputElement).select()"
      >
      <p
        v-if="failed"
        role="alert"
      >
        {{ translate('projects.renameFailed') }}
      </p>
      <div class="rename-project__actions">
        <GcButton
          variant="secondary"
          :disabled="pending"
          @click="emit('close')"
        >
          {{ translate('projects.cancel') }}
        </GcButton>
        <GcButton
          type="submit"
          :disabled="pending || !valid"
        >
          {{ translate('projects.save') }}
        </GcButton>
      </div>
    </form>
  </dialog>
</template>

<style scoped>
.rename-project {
  width: min(360px, calc(100vw - 32px)); padding: 20px;
  background: var(--runne-surface); color: var(--runne-text-primary);
  border: 1px solid var(--runne-border); border-radius: 10px;
  box-shadow: 0 12px 40px #0004;
}
.rename-project::backdrop { background: #0005; }
form { display: grid; gap: 12px; }
h2 { margin: 0; font-size: 16px; }
label { font-size: 12px; color: var(--runne-text-secondary); }
input {
  width: 100%; padding: 8px; border: 1px solid var(--runne-border); border-radius: 5px;
  background: var(--runne-surface); color: inherit; font: inherit;
}
input:focus-visible { outline: 2px solid var(--runne-accent); outline-offset: 1px; }
p { font-size: 12px; color: var(--runne-error-coral); }
.rename-project__actions { display: flex; justify-content: flex-end; gap: 8px; }
</style>
