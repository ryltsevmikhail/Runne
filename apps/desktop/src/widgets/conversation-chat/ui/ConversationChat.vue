<script setup lang="ts">
import { GcAlert, GcButton, GcTextarea } from '@runne/product/shared/ui'

import {
  useConversationChat,
  type ConversationChatOptions,
} from '../model/useConversationChat'
import { translate } from '@/shared/i18n'

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
        <span class="conversation-chat__kicker">{{ translate('conversation.kicker') }}</span>
        <h2 id="conversation-title">
          {{ translate('conversation.title') }}
        </h2>
      </div>
      <span
        class="conversation-chat__runtime"
        :class="{ 'conversation-chat__runtime--live': runtimeState === 'live' && recovery === 'live' }"
      >
        {{ translate('conversation.runtime', { status: recovery === 'live' ? runtimeState : recovery }) }}
      </span>
    </header>

    <div
      v-if="loading"
      class="conversation-chat__state"
      aria-live="polite"
    >
      {{ translate('conversation.connecting') }}
    </div>

    <div
      v-else-if="unavailable"
      class="conversation-chat__state"
      role="alert"
    >
      <GcAlert
        level="error"
        :title="translate('conversation.unavailable')"
      >
        {{ translate('conversation.retryMessage') }}
      </GcAlert>
      <GcButton
        variant="secondary"
        @click="loadConversation"
      >
        {{ translate('conversation.retry') }}
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
            {{ resyncing ? translate('conversation.resyncing') : translate('conversation.resync') }}
          </GcButton>
        </div>
        <ol
          class="conversation-chat__messages"
          :aria-label="translate('conversation.messages')"
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
              {{ message.role === 'user' ? translate('conversation.you') : 'Runne' }}
            </span>
            <p>{{ message.text }}</p>
          </li>
          <li
            v-if="snapshot?.messages.length === 0"
            class="conversation-chat__empty"
          >
            {{ translate('conversation.empty') }}
          </li>
        </ol>
      </div>

      <form
        class="conversation-chat__composer"
        @submit.prevent="submitMessage"
      >
        <GcTextarea
          v-model="draft"
          :label="translate('conversation.message')"
          :placeholder="translate('conversation.placeholder')"
          :rows="3"
          :state="canCompose ? 'default' : 'disabled'"
        />
        <GcButton
          :disabled="!canSend"
          type="submit"
        >
          {{ sending ? translate('conversation.running') : translate('conversation.send') }}
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
  color: var(--runne-text-primary);
  text-align: left;
}

.conversation-chat__header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--runne-space-lg);
  padding: var(--runne-space-md) var(--runne-space-lg);
  border-bottom: 1px solid var(--runne-border);
}

.conversation-chat__kicker,
.conversation-chat__role {
  color: var(--runne-ui-muted);
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
  color: var(--runne-ui-muted);
  font-size: 11px;
}

.conversation-chat__runtime--live {
  color: var(--runne-success-mint);
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
  gap: var(--runne-space-md);
  margin: 0;
  padding: var(--runne-space-xs) var(--runne-space-lg);
  border-bottom: 1px solid var(--runne-border);
  color: var(--runne-ui-muted);
  font-size: 11px;
}

.conversation-chat__messages {
  display: flex;
  min-height: 0;
  flex-direction: column;
  gap: var(--runne-space-md);
  overflow-y: auto;
  margin: 0;
  padding: var(--runne-space-lg);
  list-style: none;
}

.conversation-chat__message {
  max-width: 82%;
  padding: var(--runne-space-md);
  border: 1px solid var(--runne-border);
  border-radius: var(--runne-radius-lg);
  background: var(--runne-surface-raised);
}

.conversation-chat__message--user {
  align-self: flex-end;
  border-color: color-mix(in srgb, var(--runne-accent) 35%, var(--runne-border));
}

.conversation-chat__message p {
  margin: var(--runne-space-xs) 0 0;
  color: var(--runne-text-primary);
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
  gap: var(--runne-space-md);
  height: 100%;
  color: var(--runne-ui-muted);
  font-size: 12px;
  text-align: center;
}

.conversation-chat__composer {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  align-items: end;
  gap: var(--runne-space-md);
  padding: var(--runne-space-md) var(--runne-space-lg);
  border-top: 1px solid var(--runne-border);
  background: var(--runne-surface);
}
</style>
