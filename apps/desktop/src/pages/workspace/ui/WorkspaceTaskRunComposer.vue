<script setup lang="ts">
import { GcButton } from '@runne/product/shared/ui'
import { computed, ref, type PropType } from 'vue'
import { useRouter } from 'vue-router'
import { openWorkspaceConversation } from '@/entities/conversation'
import { submitTaskRun } from '@/entities/task-run'
import { translate } from '@/shared/i18n'

type OpenConversation = typeof openWorkspaceConversation
type Submit = typeof submitTaskRun
const MAX_TASK_RUN_PROMPT_BYTES = 64 * 1024
const props = defineProps({
  workspaceId: { type: String, required: true },
  disabled: { type: Boolean, default: false },
  openConversation: { type: Function as PropType<OpenConversation>, default: openWorkspaceConversation },
  submit: { type: Function as PropType<Submit>, default: submitTaskRun },
})
const router = useRouter()
const prompt = ref('')
const submitting = ref(false)
const error = ref(false)
const workspaceChanged = ref(false)
const promptTooLong = computed(() => new TextEncoder().encode(prompt.value).length > MAX_TASK_RUN_PROMPT_BYTES)

async function submitPrompt() {
  if (submitting.value || props.disabled || prompt.value.trim().length === 0 || promptTooLong.value) return
  const workspaceId = props.workspaceId
  submitting.value = true
  error.value = false
  workspaceChanged.value = false
  try {
    const conversation = await props.openConversation(workspaceId)
    if (props.workspaceId !== workspaceId) {
      workspaceChanged.value = true
      return
    }
    const acknowledgement = await props.submit(conversation.conversationId, workspaceId, prompt.value)
    await router.push({ name: 'task-run', params: { taskRunId: acknowledgement.taskRunId } })
    prompt.value = ''
  }
  catch {
    error.value = true
  }
  finally {
    submitting.value = false
  }
}
</script>

<template>
  <form
    class="task-run-composer"
    aria-labelledby="task-run-composer-title"
    @submit.prevent="submitPrompt"
  >
    <h2 id="task-run-composer-title">
      {{ translate('taskRunComposer.title') }}
    </h2>
    <label for="task-run-prompt">{{ translate('taskRunComposer.promptLabel') }}</label>
    <textarea
      id="task-run-prompt"
      v-model="prompt"
      :disabled="disabled || submitting"
      :placeholder="translate('taskRunComposer.placeholder')"
      rows="3"
    />
    <p
      v-if="error"
      role="alert"
    >
      {{ translate('taskRunComposer.failed') }}
    </p>
    <p
      v-if="promptTooLong"
      role="alert"
    >
      {{ translate('taskRunComposer.promptTooLong') }}
    </p>
    <p
      v-if="workspaceChanged"
      role="alert"
    >
      {{ translate('taskRunComposer.workspaceChanged') }}
    </p>
    <GcButton
      type="submit"
      :disabled="disabled || submitting || prompt.trim().length === 0 || promptTooLong"
    >
      {{ submitting ? translate('taskRunComposer.submitting') : translate('taskRunComposer.submit') }}
    </GcButton>
  </form>
</template>

<style scoped>
.task-run-composer { display: grid; gap: 0.55rem; padding: 0.9rem 0; border-bottom: 1px solid var(--gc-border, #343a40); }
.task-run-composer h2 { margin: 0; font-size: 0.95rem; }
.task-run-composer label { font-size: 0.82rem; font-weight: 600; }
.task-run-composer textarea { width: 100%; resize: vertical; padding: 0.65rem; color: inherit; background: var(--gc-surface, transparent); border: 1px solid var(--gc-border, #555); border-radius: 0.4rem; font: inherit; }
.task-run-composer [role="alert"] { margin: 0; color: var(--gc-danger, #c33); font-size: 0.85rem; }
</style>
