<script setup lang="ts">
import { translate } from '@/shared/i18n'
import { ConversationChat } from '@/widgets/conversation-chat'
</script>

<template>
  <main class="text-chat-page">
    <p class="text-chat-page__notice">{{ translate('conversation.textOnlyNotice') }}</p>
    <ConversationChat text-only />
  </main>
</template>

<style scoped>
.text-chat-page { display: flex; height: 100%; flex-direction: column; overflow: hidden; }
.text-chat-page__notice { margin: 0; padding: 10px 20px; color: var(--runne-text-secondary); font-size: 12px; }
</style>
