import { ref, watch, type Ref } from 'vue'

// One bounded retry per failure episode while live; resets on settled
// success or a runtime/workspace generation change. Any in-flight page load
// hard-blocks scheduling. Returns the teardown function.
export function createFilesRetryController(
  read: () => { status: string; error: boolean; loading: boolean; id: string },
  retry: (id: string) => void,
): () => void {
  let disposed = false
  let handled = false
  let lifecycle = ''
  let timer: ReturnType<typeof setTimeout> | undefined
  const cancelTimer = () => {
    if (timer !== undefined) clearTimeout(timer)
    timer = undefined
  }
  const stop = watch(read, ({ status, error, loading, id }) => {
    if (disposed) return
    const next = `${status}|${id}`
    if (next !== lifecycle) {
      handled = false
      lifecycle = next
      cancelTimer()
    }
    if (status === 'live' && id !== '' && !error && !loading) {
      handled = false
      cancelTimer()
    }
    if (loading) return
    if (status !== 'live' || !error || id === '' || handled) return
    handled = true
    const episodeId = id
    timer = setTimeout(() => {
      timer = undefined
      if (disposed) return
      const current = read()
      // Re-check at fire time: the episode must still be failing and no load
      // may be in flight (guards against stacked duplicate loads).
      if (current.status !== 'live' || !current.error || current.loading || current.id !== episodeId) return
      retry(episodeId)
    }, 2500)
  })
  return () => {
    disposed = true
    stop()
    cancelTimer()
  }
}

// Single-flight page loads with a bounded parallel slot: an unresolved IPC
// hard-blocks the bounded file retry; overflowing requests coalesce into one
// latest-only pending id. Returns the teardown and the in-flight count.
export function createSingleFlightLoader(
  load: (id: string) => Promise<void>,
  canRun: (id: string) => boolean = () => true,
  maxParallel = 2,
): {
  inFlight: Ref<number>
  request: (id: string) => void
  dispose: () => void
} {
  const inFlight = ref(0)
  const active = new Set<string>()
  let pendingId: string | null = null
  // An id already loading (or a full slot budget) coalesces into one
  // latest-only pending id, so a duplicate never occupies a second slot.
  function start(id: string): void {
    if (active.has(id) || inFlight.value >= maxParallel) pendingId = id
    else void run(id)
  }
  async function run(id: string): Promise<void> {
    active.add(id)
    inFlight.value += 1
    try {
      await load(id)
    }
    finally {
      active.delete(id)
      inFlight.value -= 1
      if (pendingId !== null && !active.has(pendingId) && canRun(pendingId)) {
        const id = pendingId
        pendingId = null
        void run(id)
      }
    }
  }
  return {
    inFlight,
    request: start,
    dispose: () => {
      pendingId = null
      active.clear()
    },
  }
}
