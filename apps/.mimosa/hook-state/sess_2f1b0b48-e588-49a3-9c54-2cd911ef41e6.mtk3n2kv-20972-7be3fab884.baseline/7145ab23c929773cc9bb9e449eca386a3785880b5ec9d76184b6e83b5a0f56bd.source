import { ref, watch, type Ref } from 'vue'

import { readProcessOutput, type ProcessOutputChunk } from '../api/process'

export function useProcessOutput(
  processId: Readonly<Ref<string | null>>,
  runtimeStatus: Readonly<Ref<string>>,
) {
  const chunks = ref<readonly ProcessOutputChunk[]>([])
  const loading = ref(false)
  const error = ref(false)

  async function refresh() {
    chunks.value = []
    error.value = false
    if (processId.value === null || runtimeStatus.value !== 'live') return
    loading.value = true
    try {
      chunks.value = (await readProcessOutput(processId.value, 0, 64)).chunks
    }
    catch {
      error.value = true
    }
    finally {
      loading.value = false
    }
  }

  watch([runtimeStatus, processId], () => { void refresh() }, { immediate: true })
  return { chunks, loading, error, refresh }
}
