export type TransientConnectResult =
  | { readonly kind: 'connected'; readonly value: unknown }
  | { readonly kind: 'cancelled' }

export async function connectThroughTransientWindow(
  connect: () => Promise<unknown>,
  shouldContinue: () => boolean,
  wait: () => Promise<void>,
  maxRetries: number,
): Promise<TransientConnectResult> {
  for (let retry = 0; retry <= maxRetries; retry += 1) {
    if (!shouldContinue()) return { kind: 'cancelled' }
    try {
      return { kind: 'connected', value: await connect() }
    }
    catch (error) {
      const disposition = (error as { disposition?: unknown } | null | undefined)?.disposition
      if (disposition !== 'transient' || retry === maxRetries) throw error
      await wait()
    }
  }
  return { kind: 'cancelled' }
}
