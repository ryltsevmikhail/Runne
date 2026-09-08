import { isTauri } from '@tauri-apps/api/core'
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'

import type {
  ConversationSession,
  ConversationSnapshot,
  ConversationTimelineListener,
} from '@/entities/conversation'
import {
  openWorkspaceConversation,
  subscribeWorkspaceConversation,
} from '@/entities/conversation'
import {
  connectRuntime,
  type RuntimeConnectionState,
} from '@/shared/api/platform/bootstrap'
import { translate } from '@/shared/i18n'

export type Connect = () => Promise<RuntimeConnectionState>
export type OpenConversation = (workspaceId: string) => Promise<ConversationSnapshot>
export type SubscribeConversation = (
  workspaceId: string,
  initialSnapshot: ConversationSnapshot,
  onTimeline: ConversationTimelineListener,
) => Promise<ConversationSession>

export interface ConversationChatOptions {
  workspaceId: string
  connect?: Connect | undefined
  openConversation?: OpenConversation | undefined
  subscribeConversation?: SubscribeConversation | undefined
}

async function defaultConnect(): Promise<RuntimeConnectionState> {
  return isTauri() ? connectRuntime() : 'unconfigured'
}

async function defaultOpenConversation(workspaceId: string): Promise<ConversationSnapshot> {
  if (!isTauri()) {
    throw new Error('runtime unavailable')
  }
  return openWorkspaceConversation(workspaceId)
}

async function defaultSubscribeConversation(
  workspaceId: string,
  initialSnapshot: ConversationSnapshot,
  onTimeline: ConversationTimelineListener,
): Promise<ConversationSession> {
  if (!isTauri()) {
    throw new Error('runtime unavailable')
  }
  return subscribeWorkspaceConversation(workspaceId, initialSnapshot, onTimeline)
}

export function useConversationChat(options: ConversationChatOptions) {
  const snapshot = ref<ConversationSnapshot | null>(null)
  const runtimeState = ref<RuntimeConnectionState>('unconfigured')
  const loading = ref(true)
  const sending = ref(false)
  const resyncing = ref(false)
  const unavailable = ref(false)
  const draft = ref('')
  let session: ConversationSession | null = null
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
  const canResync = computed(() => (
    recovery.value === 'resync_required'
    && session !== null
    && !loading.value
    && !resyncing.value
  ))
  const statusCopy = computed(() => {
    switch (recovery.value) {
      case 'live':
        return null
      case 'reconnecting':
        return translate('conversation.reconnecting')
      case 'incompatible':
        return translate('conversation.incompatible')
      case 'revoked':
        return translate('conversation.revoked')
      case 'resync_required':
        return translate('conversation.resyncRequired')
      case 'fatal':
        return translate('conversation.recoveryFailed')
      default:
        return null
    }
  })

  onMounted(loadConversation)
  onBeforeUnmount(() => {
    disposed = true
    loadGeneration += 1
    const current = session
    session = null
    if (current !== null) {
      void current.unsubscribe()
    }
  })

  async function loadConversation() {
    const generation = loadGeneration + 1
    loadGeneration = generation
    const current = session
    session = null
    if (current !== null) {
      await current.unsubscribe()
    }
    if (disposed || generation !== loadGeneration) {
      return
    }
    loading.value = true
    unavailable.value = false
    try {
      runtimeState.value = await (options.connect ?? defaultConnect)()
      if (runtimeState.value !== 'live') {
        throw new Error('runtime unavailable')
      }
      const initial = await (options.openConversation ?? defaultOpenConversation)(options.workspaceId)
      if (disposed || generation !== loadGeneration) {
        return
      }
      snapshot.value = initial
      const candidate = await (
        options.subscribeConversation ?? defaultSubscribeConversation
      )(
        options.workspaceId,
        initial,
        (value) => {
          if (!disposed && generation === loadGeneration) {
            snapshot.value = value
          }
        },
      )
      if (disposed || generation !== loadGeneration) {
        await candidate.unsubscribe()
        return
      }
      session = candidate
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
      const current = session
      if (current === null) {
        throw new Error('runtime unavailable')
      }
      await current.sendMessage(text)
      draft.value = ''
    }
    catch {
      if (snapshot.value === null) {
        unavailable.value = true
      }
      else {
        if (snapshot.value.recovery === 'live') {
          snapshot.value = {
            ...snapshot.value,
            recovery: 'reconnecting',
          }
        }
      }
    }
    finally {
      sending.value = false
    }
  }

  async function resyncConversation() {
    if (!canResync.value) {
      return
    }
    const current = session
    if (current === null) {
      return
    }
    resyncing.value = true
    try {
      await current.resync()
    }
    catch {
      // The session restores the actionable resync-required state fail closed.
    }
    finally {
      resyncing.value = false
    }
  }

  return {
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
  }
}
