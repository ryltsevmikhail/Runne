import { isTauri } from '@tauri-apps/api/core'
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'

import type {
  ConversationSession,
  ConversationSnapshot,
  ConversationTimelineListener,
} from '@/entities/conversation'
import {
  openWorkspaceConversation,
  subscribeWorkspaceConversation,
} from '@/entities/conversation'
import type { RuntimeConnectionState } from '@/shared/api/platform/bootstrap'
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
  disabled?: boolean | undefined
  connect?: Connect | undefined
  openConversation?: OpenConversation | undefined
  subscribeConversation?: SubscribeConversation | undefined
}

async function defaultConnect(): Promise<RuntimeConnectionState> {
  // No injected connector and no session context: fail closed instead of
  // bypassing the authoritative session controller with a raw handshake.
  return 'unconfigured'
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

export function useConversationChat(
  options: ConversationChatOptions,
  sessionConnect?: (allowRetry: boolean) => Promise<RuntimeConnectionState>,
) {
  const snapshot = ref<ConversationSnapshot | null>(null)
  const runtimeState = ref<RuntimeConnectionState>('unconfigured')
  const loading = ref(true)
  const sending = ref(false)
  const resyncing = ref(false)
  const unavailable = ref(false)
  const draft = ref('')
  let session: ConversationSession | null = null
  let loadGeneration = 0
  let loadInFlight = false
  let pendingReload = false
  let disposed = false
  const recovery = computed(() => snapshot.value?.recovery ?? 'live')
  const canCompose = computed(() => (
    options.disabled !== true
    && runtimeState.value === 'live'
    && recovery.value === 'live'
    && !loading.value
    && !sending.value
    && !unavailable.value
  ))
  const canSend = computed(() => (
    canCompose.value
    && draft.value.length > 0
  ))
  const canResync = computed(() => (
    options.disabled !== true
    && recovery.value === 'resync_required'
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

  onMounted(() => { void loadConversation(false, false) })
  // A read-only window must refresh once the session turns mutable again;
  // reloads coalesce single-flight instead of stacking per runtime cycle.
  watch(() => options.disabled, (disabled, wasDisabled) => {
    if (disabled === true) {
      pendingReload = false
      return
    }
    if (wasDisabled === true && sessionConnect) {
      if (loading.value) {
        pendingReload = true
        return
      }
      void loadConversation(true, false)
    }
  })

  // Bounded recovery: at most two consecutive resubscribes when the
  // conversation subscription drops; a live subscription refills the budget.
  let recoveryReloads = 0
  watch(recovery, (value, was) => {
    if (value !== 'reconnecting' || was === 'reconnecting') return
    if (!sessionConnect || options.disabled === true || recoveryReloads >= 2) return
    recoveryReloads += 1
    void loadConversation(true, false)
  })

  onBeforeUnmount(() => {
    disposed = true
    loadGeneration += 1
    const current = session
    session = null
    if (current !== null) {
      void current.unsubscribe()
    }
  })

  async function loadConversation(skipConnect = false, allowRetry = false) {
    // Single-flight: in-flight open/subscribe coalesces into one pending reload.
    if (loadInFlight) {
      pendingReload = true
      return
    }
    loadInFlight = true
    loading.value = true
    const generation = loadGeneration + 1
    loadGeneration = generation
    const current = session
    session = null
    // A stale unsubscribe failure must not fence the fresh load.
    if (current !== null) void current.unsubscribe().catch(() => {})
    if (disposed || generation !== loadGeneration) {
      loadInFlight = false
      return
    }
    unavailable.value = false
    try {
      // The recovery edge must not re-run the raw handshake: it would replace
      // the authoritative client and rotate mutation gates behind the
      // controller's back. The proven session connector wins over injected
      // test connectors; the bare-options default fails closed. An automatic
      // (mount/reload) edge never re-arms a terminal session: only an
      // explicit user retry may.
      runtimeState.value = skipConnect
        ? 'live'
        : await (sessionConnect
          ? sessionConnect(allowRetry)
          : options.connect
            ? options.connect()
            : defaultConnect())
      if (runtimeState.value !== 'live') throw new Error('runtime unavailable')
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
      // A live subscription is the proof that refills the bounded budget.
      recoveryReloads = 0
    }
    catch {
      if (!disposed && generation === loadGeneration) {
        if (snapshot.value === null) unavailable.value = true
        else if (snapshot.value.recovery === 'live') {
          snapshot.value = { ...snapshot.value, recovery: 'reconnecting' }
        }
      }
    }
    finally {
      loadInFlight = false
      if (!disposed && generation === loadGeneration) {
        loading.value = false
        // A reload requested mid-flight runs once now, never accumulating.
        if (pendingReload && sessionConnect) {
          pendingReload = false
          void loadConversation(true, false)
        }
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
