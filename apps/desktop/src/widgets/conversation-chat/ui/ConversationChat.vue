<script setup lang="ts">
import { GcAlert, GcButton, GcTextarea } from '@gocode/product/shared/ui'
import { isTauri } from '@tauri-apps/api/core'
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'

import type {
  ConversationSnapshot,
  ConversationTimelineListener,
  ConversationUnsubscribe,
} from '@/entities/conversation'
import {
  openProjectConversation,
  sendProjectMessage,
  subscribeProjectConversation,
} from '@/entities/conversation'
import {
  connectRuntime,
  type RuntimeConnectionState,
} from '@/shared/api/platform/bootstrap'

type Connect = () => Promise<RuntimeConnectionState>
type OpenConversation = (projectId: number) => Promise<ConversationSnapshot>
type SendMessage = (projectId: number, text: string) => Promise<ConversationSnapshot>
type SubscribeConversation = (
  projectId: number,
  initialSnapshot: ConversationSnapshot,
  onTimeline: ConversationTimelineListener,
) => Promise<ConversationUnsubscribe>

async function defaultConnect(): Promise<RuntimeConnectionState> {
  return isTauri() ? connectRuntime() : 'unconfigured'
}

async function defaultOpenConversation(projectId: number): Promise<ConversationSnapshot> {
  if (!isTauri()) {
    throw new Error('runtime unavailable')
  }
  return openProjectConversation(projectId)
}

async function defaultSendMessage(
  projectId: number,
  text: string,
): Promise<ConversationSnapshot> {
  if (!isTauri()) {
    throw new Error('runtime unavailable')
  }
  return sendProjectMessage(projectId, text)
}

async function defaultSubscribeConversation(
  projectId: number,
  initialSnapshot: ConversationSnapshot,
  onTimeline: ConversationTimelineListener,
): Promise<ConversationUnsubscribe> {
  if (!isTauri()) {
    throw new Error('runtime unavailable')
  }
  return subscribeProjectConversation(projectId, initialSnapshot, onTimeline)
}

const props = defineProps<{
  projectId: number
  connect?: Connect
  openConversation?: OpenConversation
  sendMessage?: SendMessage
  subscribeConversation?: SubscribeConversation
}>()

const snapshot = ref<ConversationSnapshot | null>(null)
const runtimeState = ref<RuntimeConnectionState>('unconfigured')
const loading = ref(true)
const sending = ref(false)
const unavailable = ref(false)
const draft = ref('')
let unsubscribe: ConversationUnsubscribe | null = null
let loadGeneration = 0
let disposed = false
const recovery = computed(() => snapshot.value?.recovery ?? 'live')
const canCompose = computed(() => (
  runtimeState.value === 'live'
  && recovery.value === 'live'
  && !loading.value
  && !sending.value
))
const canSend = computed(() => (
  canCompose.value
  && draft.value.length > 0
))
const statusCopy = computed(() => {
  switch (recovery.value) {
    case 'live':
      return null
    case 'reconnecting':
      return 'Reconnecting — confirmed messages remain read-only.'
    case 'incompatible':
      return 'Runtime version is incompatible.'
    case 'revoked':
      return 'Runtime access was revoked.'
    case 'resync_required':
      return 'Conversation resync is required.'
    case 'fatal':
      return 'Conversation recovery failed.'
    default:
      return null
  }
})

onMounted(loadConversation)
onBeforeUnmount(() => {
  disposed = true
  loadGeneration += 1
  const current = unsubscribe
  unsubscribe = null
  if (current !== null) {
    void current()
  }
})

async function loadConversation() {
  const generation = loadGeneration + 1
  loadGeneration = generation
  const current = unsubscribe
  unsubscribe = null
  if (current !== null) {
    await current()
  }
  if (disposed || generation !== loadGeneration) {
    return
  }
  loading.value = true
  unavailable.value = false
  try {
    runtimeState.value = await (props.connect ?? defaultConnect)()
    if (runtimeState.value !== 'live') {
      throw new Error('runtime unavailable')
    }
    const initial = await (props.openConversation ?? defaultOpenConversation)(props.projectId)
    if (disposed || generation !== loadGeneration) {
      return
    }
    snapshot.value = initial
    const candidate = await (
      props.subscribeConversation ?? defaultSubscribeConversation
    )(
      props.projectId,
      initial,
      (value) => {
        if (!disposed && generation === loadGeneration) {
          snapshot.value = value
        }
      },
    )
    if (disposed || generation !== loadGeneration) {
      await candidate()
      return
    }
    unsubscribe = candidate
  }
  catch {
    if (!disposed && generation === loadGeneration) {
      if (snapshot.value === null) {
        unavailable.value = true
      }
      else {
        snapshot.value = {
          ...snapshot.value,
          recovery: 'reconnecting',
        }
      }
    }
  }
  finally {
    if (!disposed && generation === loadGeneration) {
      loading.value = false
    }
  }
}

async function submitMessage() {
  if (!canSend.value) {
    return
  }
  sending.value = true
  unavailable.value = false
  const text = draft.value
  try {
    snapshot.value = await (props.sendMessage ?? defaultSendMessage)(props.projectId, text)
    draft.value = ''
  }
  catch {
    if (snapshot.value === null) {
      unavailable.value = true
    }
    else {
      snapshot.value = {
        ...snapshot.value,
        recovery: 'reconnecting',
      }
    }
  }
  finally {
    sending.value = false
  }
}
</script>

<template>
  <section
    class="conversation-chat"
    aria-labelledby="conversation-title"
    :aria-busy="loading || sending"
  >
    <header class="conversation-chat__header">
      <div>
        <span class="conversation-chat__kicker">Conversation</span>
        <h2 id="conversation-title">
          Coding agent
        </h2>
      </div>
      <span
        class="conversation-chat__runtime"
        :class="{ 'conversation-chat__runtime--live': runtimeState === 'live' && recovery === 'live' }"
      >
        Runtime {{ recovery === 'live' ? runtimeState : recovery }}
      </span>
    </header>

    <div
      v-if="loading"
      class="conversation-chat__state"
      aria-live="polite"
    >
      Connecting to runtime…
    </div>

    <div
      v-else-if="unavailable"
      class="conversation-chat__state"
      role="alert"
    >
      <GcAlert
        level="error"
        title="Runtime unavailable"
      >
        Start the local runtime and retry the connection.
      </GcAlert>
      <GcButton
        variant="secondary"
        @click="loadConversation"
      >
        Retry
      </GcButton>
    </div>

    <template v-else>
      <div class="conversation-chat__timeline">
        <p
          v-if="statusCopy !== null"
          class="conversation-chat__recovery"
          role="status"
        >
          {{ statusCopy }}
        </p>
        <ol
          class="conversation-chat__messages"
          aria-label="Conversation messages"
          aria-live="polite"
        >
          <li
            v-for="message in snapshot?.messages ?? []"
            :key="message.messageId"
            class="conversation-chat__message"
            :class="`conversation-chat__message--${message.role}`"
            :data-message-id="message.messageId"
            :data-message-role="message.role"
          >
            <span class="conversation-chat__role">
              {{ message.role === 'user' ? 'You' : 'GOCODE' }}
            </span>
            <p>{{ message.text }}</p>
          </li>
          <li
            v-if="snapshot?.messages.length === 0"
            class="conversation-chat__empty"
          >
            Send a message to start this project conversation.
          </li>
        </ol>
      </div>

      <form
        class="conversation-chat__composer"
        @submit.prevent="submitMessage"
      >
        <GcTextarea
          v-model="draft"
          label="Message"
          placeholder="Ask GOCODE to work on this project"
          :rows="3"
          :state="canCompose ? 'default' : 'disabled'"
        />
        <GcButton
          :disabled="!canSend"
          type="submit"
        >
          {{ sending ? 'Running…' : 'Send' }}
        </GcButton>
      </form>
    </template>
  </section>
</template>

<style scoped>
.conversation-chat {
  display: grid;
  width: 100%;
  height: 100%;
  min-height: 0;
  grid-template-rows: auto minmax(0, 1fr) auto;
  color: var(--gocode-text-primary);
  text-align: left;
}

.conversation-chat__header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--gocode-space-lg);
  padding: var(--gocode-space-md) var(--gocode-space-lg);
  border-bottom: 1px solid var(--gocode-border);
}

.conversation-chat__kicker,
.conversation-chat__role {
  color: var(--gocode-ui-muted);
  font-size: 10px;
  font-weight: 700;
  letter-spacing: .06em;
  text-transform: uppercase;
}

.conversation-chat__header h2 {
  margin: 3px 0 0;
  font-size: 14px;
}

.conversation-chat__runtime {
  color: var(--gocode-ui-muted);
  font-size: 11px;
}

.conversation-chat__runtime--live {
  color: var(--gocode-success-mint);
}

.conversation-chat__timeline {
  display: grid;
  min-height: 0;
  grid-template-rows: auto minmax(0, 1fr);
}

.conversation-chat__recovery {
  margin: 0;
  padding: var(--gocode-space-xs) var(--gocode-space-lg);
  border-bottom: 1px solid var(--gocode-border);
  color: var(--gocode-ui-muted);
  font-size: 11px;
}

.conversation-chat__messages {
  display: flex;
  min-height: 0;
  flex-direction: column;
  gap: var(--gocode-space-md);
  overflow-y: auto;
  margin: 0;
  padding: var(--gocode-space-lg);
  list-style: none;
}

.conversation-chat__message {
  max-width: 82%;
  padding: var(--gocode-space-md);
  border: 1px solid var(--gocode-border);
  border-radius: var(--gocode-radius-lg);
  background: var(--gocode-surface-raised);
}

.conversation-chat__message--user {
  align-self: flex-end;
  border-color: color-mix(in srgb, var(--gocode-accent) 35%, var(--gocode-border));
}

.conversation-chat__message p {
  margin: var(--gocode-space-xs) 0 0;
  color: var(--gocode-text-primary);
  font-size: 13px;
  line-height: 1.55;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}

.conversation-chat__empty,
.conversation-chat__state {
  display: grid;
  place-items: center;
  align-content: center;
  gap: var(--gocode-space-md);
  height: 100%;
  color: var(--gocode-ui-muted);
  font-size: 12px;
  text-align: center;
}

.conversation-chat__composer {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  align-items: end;
  gap: var(--gocode-space-md);
  padding: var(--gocode-space-md) var(--gocode-space-lg);
  border-top: 1px solid var(--gocode-border);
  background: var(--gocode-surface);
}
</style>
