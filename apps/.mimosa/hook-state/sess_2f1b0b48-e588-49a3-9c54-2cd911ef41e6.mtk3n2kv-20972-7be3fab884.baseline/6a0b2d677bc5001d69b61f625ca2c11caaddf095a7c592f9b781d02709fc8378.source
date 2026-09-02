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
  observeBootstrap(value: unknown): RuntimeSessionSnapshot
}

const runtimeSessionKey: InjectionKey<RuntimeSessionContext> = Symbol('runtime-session')

export function createRuntimeSessionContext(port: RuntimeSessionController): RuntimeSessionContext {
  const snapshot = shallowRef(port.snapshot())
  const update = async (operation: () => Promise<RuntimeSessionSnapshot>) => {
    snapshot.value = await operation()
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
    observeBootstrap(value) {
      snapshot.value = port.observeBootstrap(value)
      return snapshot.value
    },
  }
}

export function provideRuntimeSession(context: RuntimeSessionContext): void {
  provide(runtimeSessionKey, context)
}

export function tryUseRuntimeSession(): RuntimeSessionContext | undefined {
  return inject(runtimeSessionKey, undefined)
}
