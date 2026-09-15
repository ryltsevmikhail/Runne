import {
  inject,
  provide,
  readonly,
  shallowRef,
  type InjectionKey,
  type Ref,
} from 'vue'

import type { RuntimeSessionController, RuntimeSessionSnapshot } from './runtime-session'

export interface RuntimeSessionContext {
  readonly snapshot: Readonly<Ref<RuntimeSessionSnapshot>>
  connect(): Promise<RuntimeSessionSnapshot>
  retry(): Promise<RuntimeSessionSnapshot>
  close(): Promise<void>
  observeBootstrap(value: unknown, ticket?: number): RuntimeSessionSnapshot
  sessionTicket(): number
  ticketFenced(ticket: number | undefined): boolean
}

const runtimeSessionKey: InjectionKey<RuntimeSessionContext> = Symbol('runtime-session')

export function createRuntimeSessionContext(port: RuntimeSessionController): RuntimeSessionContext {
  const snapshot = shallowRef(port.snapshot())
  // Publish the controller's current snapshot after the operation settles:
  // a revocation or close arriving meanwhile must not be overwritten by the
  // operation's stale return value.
  const update = async (operation: () => Promise<RuntimeSessionSnapshot>) => {
    await operation()
    snapshot.value = port.snapshot()
    return snapshot.value
  }
  return {
    snapshot: readonly(snapshot),
    connect: () => update(port.connect),
    retry: () => update(port.retry),
    async close() {
      await port.close()
      snapshot.value = port.snapshot()
    },
    observeBootstrap(value, ticket) {
      snapshot.value = port.observeBootstrap(value, ticket)
      return snapshot.value
    },
    sessionTicket: () => port.sessionTicket(),
    ticketFenced: (ticket: number | undefined) => port.ticketFenced(ticket),
  }
}

export function provideRuntimeSession(context: RuntimeSessionContext): void {
  provide(runtimeSessionKey, context)
}

export function tryUseRuntimeSession(): RuntimeSessionContext | undefined {
  return inject(runtimeSessionKey, undefined)
}
