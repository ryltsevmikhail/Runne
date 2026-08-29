<script setup lang="ts">
import { GcAlert, GcButton, GcTextarea } from '@gocode/product/shared/ui'

import {
  useConversationChat,
  type ConversationChatOptions,
} from '../model/useConversationChat'

const props = defineProps<ConversationChatOptions>()

const {
  snapshot,
  runtimeState,
  loading,
  sending,
  resyncing,
  unavailable,
  draft,
  recovery,
  canCompose,
  canSend,
  canResync,
  statusCopy,
  loadConversation,
  submitMessage,
  resyncConversation,
} = useConversationChat(props)
</script>

<template>
  <section
    class="conversation-chat"
    aria-labelledby="conversation-title"
    :aria-busy="loading || sending || resyncing"
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
        <div
          v-if="statusCopy !== null"
          class="conversation-chat__recovery"
          role="status"
        >
          <span>{{ statusCopy }}</span>
          <GcButton
            v-if="recovery === 'resync_required'"
            name="resync-conversation"
            size="sm"
            variant="secondary"
            :disabled="!canResync"
            @click="resyncConversation"
          >
            {{ resyncing ? 'Resyncing…' : 'Resync' }}
          </GcButton>
        </div>
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
              {{ message.role === 'user' ? 'You' : 'Runne' }}
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
          placeholder="Ask Runne to work on this project"
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
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--gocode-space-md);
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
