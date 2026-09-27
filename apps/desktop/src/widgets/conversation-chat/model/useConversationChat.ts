import { isTauri } from '@tauri-apps/api/core'
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'

import type { ConversationSession, ConversationSnapshot, ConversationTimelineListener } from '@/entities/conversation'
import {
  openTextOnlyConversation,
  openWorkspaceConversation,
  subscribeTextOnlyConversation,
  subscribeWorkspaceConversation,
} from '@/entities/conversation'
import type { RuntimeConnectionState } from '@/shared/api/platform/bootstrap'
import { conversationRecoveryCopy } from './recovery-copy'

export type Connect = () => Promise<RuntimeConnectionState>
export type OpenConversation = (workspaceId: string) => Promise<ConversationSnapshot>
export type SubscribeConversation = (
  workspaceId: string,
  initialSnapshot: ConversationSnapshot,
  onTimeline: ConversationTimelineListener,
) => Promise<ConversationSession>

export interface ConversationChatOptions {
  workspaceId?: string | undefined
  textOnly?: boolean | undefined
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
  sessionReady?: () => boolean,
) {
  const snapshot = ref<ConversationSnapshot | null>(null)
  const runtimeState = ref<RuntimeConnectionState>('unconfigured')
  const loading = ref(true)
  const sending = ref(false)
  const resyncing = ref(false)
  const unavailable = ref(false)
  const draft = ref('')
  const sessionIsReady = computed(() => sessionReady?.() ?? true)
  let session: ConversationSession | null = null
  let loadGeneration = 0
  let loadInFlight = false
  let pendingReload = false
  let disposed = false
  const recovery = computed(() => snapshot.value?.recovery ?? 'live')
  const canCompose = computed(() => (
    options.disabled !== true
    && sessionIsReady.value
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
    && sessionIsReady.value
    && recovery.value === 'resync_required'
    && session !== null
    && !loading.value
    && !resyncing.value
  ))
  const statusCopy = computed(() => conversationRecoveryCopy(recovery.value))
  const canAutomaticallyReload = () => snapshot.value === null
    || recovery.value === 'live'
    || recovery.value === 'reconnecting'

  onMounted(() => { void loadConversation(false) })
  // A read-only window must refresh once the session turns mutable again;
  // reloads coalesce single-flight instead of stacking per runtime cycle.
  watch(() => options.disabled, (disabled, wasDisabled) => {
    if (disabled === true) {
      pendingReload = false
      return
    }
    if (wasDisabled === true && sessionConnect && canAutomaticallyReload()) {
      if (loading.value) {
        pendingReload = true
        return
      }
      void loadConversation(false)
    }
  })

  // Bounded recovery: at most two consecutive resubscribes when the
  // conversation subscription drops; a live subscription refills the budget.
  let recoveryReloads = 0
  watch(
    () => [recovery.value, sessionIsReady.value] as const,
    ([value, ready], [was, wasReady]) => {
      const sessionRecovered = ready && !wasReady && canAutomaticallyReload()
      const streamDropped = value === 'reconnecting' && was !== 'reconnecting'
      if ((!sessionRecovered && !streamDropped) || !ready) return
      if (!sessionConnect || options.disabled === true) return
      if (sessionRecovered) recoveryReloads = 0
      if (recoveryReloads >= 2) return
      recoveryReloads += 1
      void loadConversation(false)
    },
  )

  onBeforeUnmount(() => {
    disposed = true
    loadGeneration += 1
    const current = session
    session = null
    if (current !== null) {
      void current.unsubscribe()
    }
  })

  async function loadConversation(allowRetry = false) {
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
      // Every reload revalidates the injected authoritative session. It must
      // not infer readiness from a stale conversation snapshot.
      runtimeState.value = await (sessionConnect
        ? sessionConnect(allowRetry)
        : options.connect
          ? options.connect()
          : defaultConnect())
      if (runtimeState.value !== 'live') throw new Error('runtime unavailable')
      const initial = options.textOnly === true
        ? await openTextOnlyConversation()
        : await (options.openConversation ?? defaultOpenConversation)(options.workspaceId ?? '')
      if (disposed || generation !== loadGeneration) {
        return
      }
      snapshot.value = initial
      const onTimeline = (value: ConversationSnapshot) => {
          if (!disposed && generation === loadGeneration) {
            snapshot.value = value
          }
        }
      const candidate = options.textOnly === true
        ? await subscribeTextOnlyConversation(initial, onTimeline)
        : await (options.subscribeConversation ?? defaultSubscribeConversation)(
            options.workspaceId ?? '', initial, onTimeline,
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
          if (canAutomaticallyReload()) void loadConversation(false)
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
