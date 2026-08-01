import { type Page } from '@playwright/test'

export const initialSnapshot = {
  conversationId: '018f2e3a-7000-7000-8000-000000000101',
  projectionRevision: 3,
  streamVersion: 3,
  messages: [
    {
      messageId: '018f2e3a-7000-7000-8000-000000000102',
      role: 'user',
      taskRunId: '018f2e3a-7000-7000-8000-000000000103',
      attemptId: '018f2e3a-7000-7000-8000-000000000104',
      text: 'hello',
      committedAt: 1_753_800_000_001,
    },
    {
      messageId: '018f2e3a-7000-7000-8000-000000000105',
      role: 'assistant',
      taskRunId: '018f2e3a-7000-7000-8000-000000000103',
      attemptId: '018f2e3a-7000-7000-8000-000000000104',
      text: 'GOCODE local response: hello',
      committedAt: 1_753_800_000_002,
    },
  ],
  recovery: 'live',
} as const

export const nextUpdate = {
  kind: 'update',
  conversationId: initialSnapshot.conversationId,
  projectionRevision: 4,
  streamVersion: 4,
  message: {
    messageId: '018f2e3a-7000-7000-8000-000000000106',
    role: 'assistant',
    taskRunId: '018f2e3a-7000-7000-8000-000000000103',
    attemptId: '018f2e3a-7000-7000-8000-000000000104',
    text: 'next',
    committedAt: 1_753_800_000_003,
  },
  recovery: 'live',
} as const

export type BrowserReplayAdapter = {
  emit: (value: unknown) => void
  calls: string[]
  resyncShouldFail: boolean
  resyncSubscriptionShouldFail: boolean
}

export async function installDesktopAdapter(page: Page): Promise<void> {
  await page.addInitScript(({ snapshot }) => {
    type Callback = (payload: unknown) => void
    type TauriInternals = {
      invoke: (
        command: string,
        args?: Record<string, unknown>,
        options?: unknown,
      ) => Promise<unknown>
      transformCallback: (callback: Callback, once?: boolean) => number
      unregisterCallback: (id: number) => void
      convertFileSrc: (path: string) => string
    }
    type ReplayWindow = Window & {
      __TAURI_INTERNALS__: TauriInternals
      __GOCODE_REPLAY_TEST__: BrowserReplayAdapter
    }

    const callbacks = new Map<number, Callback>()
    let nextCallbackId = 1
    let channelCallbackId: number | null = null
    let channelIndex = 0
    let subscriptionCount = 0
    const calls: string[] = []
    const replayWindow = window as ReplayWindow
    ;(globalThis as typeof globalThis & { isTauri: boolean }).isTauri = true

    replayWindow.__GOCODE_REPLAY_TEST__ = {
      calls,
      resyncShouldFail: false,
      resyncSubscriptionShouldFail: false,
      emit(value: unknown) {
        if (channelCallbackId === null) {
          throw new Error('conversation channel is not subscribed')
        }
        const callback = callbacks.get(channelCallbackId)
        if (callback === undefined) {
          throw new Error('conversation channel callback is unavailable')
        }
        callback({ index: channelIndex, message: value })
        channelIndex += 1
      },
    }
    replayWindow.__TAURI_INTERNALS__ = {
      transformCallback(callback, once = false) {
        const id = nextCallbackId
        nextCallbackId += 1
        callbacks.set(id, once
          ? (payload) => {
              callbacks.delete(id)
              callback(payload)
            }
          : callback)
        return id
      },
      unregisterCallback(id) {
        callbacks.delete(id)
      },
      convertFileSrc(path) {
        return path
      },
      async invoke(command, args) {
        calls.push(command)
        switch (command) {
          case 'get_bootstrap':
            return { theme: 'dark', runtime: 'live' }
          case 'connect_runtime':
            return 'live'
          case 'get_project':
            return {
              id: 7,
              name: 'gocode-ui',
              path: '/workspace/gocode-ui',
              lastOpenedAt: 1_753_500_000_000,
            }
          case 'open_project_conversation':
            return snapshot
          case 'resync_project_conversation':
            await new Promise(resolve => setTimeout(resolve, 1_000))
            if (replayWindow.__GOCODE_REPLAY_TEST__.resyncShouldFail) {
              throw new Error('retention still unavailable')
            }
            return snapshot
          case 'subscribe_project_conversation': {
            subscriptionCount += 1
            const channel = args?.onUpdate as { id?: unknown } | undefined
            if (typeof channel?.id !== 'number') {
              throw new Error('typed conversation channel is required')
            }
            if (
              subscriptionCount > 1
              && replayWindow.__GOCODE_REPLAY_TEST__.resyncSubscriptionShouldFail
            ) {
              throw new Error('replacement subscription unavailable')
            }
            channelCallbackId = channel.id
            return '018f2e3a-7000-7000-8000-000000000120'
          }
          case 'ack_conversation_update':
          case 'cancel_conversation_subscription':
          case 'set_theme':
            return null
          default:
            throw new Error(`unsupported test command: ${command}`)
        }
      },
    }
  }, { snapshot: initialSnapshot })
}

export async function emitChannel(page: Page, value: unknown): Promise<void> {
  await page.evaluate((event) => {
    const replayWindow = window as Window & {
      __GOCODE_REPLAY_TEST__: BrowserReplayAdapter
    }
    replayWindow.__GOCODE_REPLAY_TEST__.emit(event)
  }, value)
}
