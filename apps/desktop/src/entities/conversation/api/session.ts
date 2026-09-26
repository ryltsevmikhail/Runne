import { Channel, invoke as tauriInvoke } from '@tauri-apps/api/core'

import {
  createConversationTimeline,
  reduceConversationTimeline,
  setConversationRecovery,
} from '../model/timeline'
import type {
  ConversationRecoveryState,
  ConversationSession,
  ConversationSnapshot,
  ConversationTimelineListener,
  ConversationUnsubscribe,
  Invoke,
} from './types'
import {
  openConversationForOwner,
  resyncConversationForOwner,
  sendMessageForOwner,
  subscribeForOwner,
} from './owner-transport'
import {
  isCanonicalId,
  parseConversationChannelEvent,
  parseConversationSnapshot,
  recoveryForError,
  sameSnapshot,
  validateWorkspaceId,
} from './validation'

export async function subscribeConversationForOwner(
  textOnly: boolean,
  workspaceId: string,
  initialSnapshot: ConversationSnapshot,
  onTimeline: ConversationTimelineListener,
  invoke: Invoke,
): Promise<ConversationSession> {
  if (!textOnly) validateWorkspaceId(workspaceId)
  const sanitizedInitial = parseConversationSnapshot(initialSnapshot)
  if (sanitizedInitial === null) {
    throw new Error('Invalid conversation response')
  }

  let timeline = createConversationTimeline(sanitizedInitial)
  let activeSubscriptionId: string | null = null
  let resyncedSnapshot: ConversationSnapshot | null = null
  let generation = 0
  let closed = false
  let processing = Promise.resolve()

  const serialize = <T>(operation: () => Promise<T>): Promise<T> => {
    const result = processing.then(operation)
    processing = result.then(
      () => undefined,
      () => undefined,
    )
    return result
  }

  const publishRecovery = (recovery: ConversationRecoveryState): void => {
    timeline = setConversationRecovery(timeline, recovery)
    onTimeline(timeline.snapshot)
  }
  const currentRecovery = (): ConversationRecoveryState => timeline.snapshot.recovery

  const cancelActive = async (): Promise<void> => {
    generation += 1
    const subscriptionId = activeSubscriptionId
    activeSubscriptionId = null
    if (subscriptionId === null) {
      return
    }
    try {
      await invoke('cancel_conversation_subscription', { subscriptionId })
    }
    catch {
      // Cancellation is best effort after a terminal or already-closed channel.
    }
  }

  const terminate = async (recovery: ConversationRecoveryState): Promise<void> => {
    publishRecovery(recovery)
    await cancelActive()
  }

  const startSubscription = async (): Promise<void> => {
    if (closed) {
      return
    }
    const currentGeneration = generation + 1
    generation = currentGeneration
    const pending: unknown[] = []
    let ready = false
    const channel = new Channel<unknown>((value) => {
      if (!ready) {
        pending.push(value)
        return
      }
      void serialize(() => handleEvent(value, currentGeneration))
    })
    const value = await subscribeForOwner(textOnly, workspaceId, channel, invoke)
    if (!isCanonicalId(value)) {
      await terminate('incompatible')
      throw new Error('Invalid conversation subscription response')
    }
    if (closed || generation !== currentGeneration) {
      try {
        await invoke('cancel_conversation_subscription', { subscriptionId: value })
      }
      catch {
        // A concurrently closed subscription may already be absent natively.
      }
      return
    }
    activeSubscriptionId = value
    ready = true
    for (const pendingValue of pending) {
      void serialize(() => handleEvent(pendingValue, currentGeneration))
    }
  }

  const reconcileAndResubscribe = async (): Promise<void> => {
    await cancelActive()
    if (closed) {
      return
    }
    const snapshot = await openConversationForOwner(textOnly, workspaceId, invoke)
    if (closed) {
      return
    }
    if (
      snapshot.conversationId !== timeline.snapshot.conversationId
      || snapshot.projectionRevision < timeline.snapshot.projectionRevision
    ) {
      await terminate('incompatible')
      return
    }
    const reconciledTimeline = createConversationTimeline(snapshot)
    await startSubscription()
    if (closed) {
      return
    }
    timeline = reconciledTimeline
    onTimeline(timeline.snapshot)
  }

  const handleEvent = async (
    value: unknown,
    eventGeneration: number,
  ): Promise<void> => {
    if (closed || eventGeneration !== generation) {
      return
    }
    const event = parseConversationChannelEvent(value)
    if (event === null) {
      await terminate('incompatible')
      return
    }
    if (event.kind === 'error') {
      await terminate(recoveryForError(event.code))
      return
    }

    const reduction = reduceConversationTimeline(timeline, event)
    if (reduction.kind === 'gap') {
      try {
        await reconcileAndResubscribe()
      }
      catch {
        if (!closed) {
          publishRecovery('fatal')
        }
      }
      return
    }
    if (reduction.kind === 'incompatible') {
      await terminate('incompatible')
      return
    }

    timeline = reduction.timeline
    if (reduction.kind === 'applied') {
      onTimeline(timeline.snapshot)
    }

    const subscriptionId = activeSubscriptionId
    if (
      closed
      || eventGeneration !== generation
      || subscriptionId === null
    ) {
      return
    }
    try {
      await invoke('ack_conversation_update', {
        subscriptionId,
        projectionRevision: event.projectionRevision,
      })
    }
    catch {
      if (!closed) {
        await terminate('reconnecting')
      }
    }
  }

  await startSubscription()

  const unsubscribe: ConversationUnsubscribe = async () => {
    if (closed) {
      return
    }
    closed = true
    await cancelActive()
  }

  const sendMessage = (text: string): Promise<ConversationSnapshot> => serialize(async () => {
    if (closed) {
      throw new Error('Conversation subscription is closed')
    }
    const snapshot = await sendMessageForOwner(textOnly, workspaceId, text, invoke)
    if (closed) {
      throw new Error('Conversation subscription is closed')
    }
    const current = timeline.snapshot
    if (
      snapshot.conversationId !== current.conversationId
      || snapshot.projectionRevision < current.projectionRevision
      || snapshot.streamVersion < current.streamVersion
      || (
        snapshot.projectionRevision === current.projectionRevision
        && !sameSnapshot(snapshot, current)
      )
    ) {
      await terminate('incompatible')
      throw new Error('Incompatible conversation response')
    }
    if (snapshot.projectionRevision === current.projectionRevision) {
      return current
    }
    timeline = createConversationTimeline(snapshot)
    onTimeline(timeline.snapshot)
    return timeline.snapshot
  })

  const resync = (): Promise<ConversationSnapshot> => serialize(async () => {
    if (closed) {
      throw new Error('Conversation subscription is closed')
    }
    if (currentRecovery() !== 'resync_required') {
      throw new Error('Conversation resync is not required')
    }
    publishRecovery('reconnecting')
    try {
      await cancelActive()
      if (closed) {
        throw new Error('Conversation subscription is closed')
      }
      let snapshot = resyncedSnapshot
      if (snapshot === null) {
        snapshot = await resyncConversationForOwner(textOnly, workspaceId, invoke)
        if (
          snapshot.conversationId !== timeline.snapshot.conversationId
          || snapshot.recovery !== 'live'
        ) {
          await terminate('incompatible')
          throw new Error('Incompatible conversation resync response')
        }
        resyncedSnapshot = snapshot
      }
      const reconciledTimeline = createConversationTimeline(snapshot)
      await startSubscription()
      if (closed) {
        throw new Error('Conversation subscription is closed')
      }
      timeline = reconciledTimeline
      resyncedSnapshot = null
      onTimeline(timeline.snapshot)
    }
    catch (error) {
      if (!closed && currentRecovery() === 'reconnecting') {
        publishRecovery('resync_required')
      }
      throw error
    }
    if (currentRecovery() !== 'live') {
      throw new Error('Conversation resync failed safely')
    }
    return timeline.snapshot
  })

  return {
    sendMessage,
    resync,
    unsubscribe,
  }
}
