import { ref, watch, type ComputedRef, type Ref } from 'vue'
import { projectTrustRevision } from '@/entities/project'
import type { CanonicalWorkspace } from '@/entities/project'

export function useWorkspaceProjectTrustRefresh(
  project: Ref<CanonicalWorkspace | null>,
  workspaceId: ComputedRef<string>,
  runtimeStatus: ComputedRef<string>,
  reload: (workspaceId: string) => void,
) {
  const activeProjectId = ref('')
  watch(() => project.value?.projectId, id => { if (id) activeProjectId.value = id })

  let observedProjectId = ''
  let observedRevision = 0
  watch(() => ({
    projectId: activeProjectId.value,
    revision: projectTrustRevision(activeProjectId.value),
  }), ({ projectId, revision }) => {
    if (!projectId) {
      observedProjectId = ''
      observedRevision = 0
      return
    }
    if (projectId !== observedProjectId) {
      observedProjectId = projectId
      observedRevision = revision
      return
    }
    if (revision === observedRevision) return
    observedRevision = revision
    const id = workspaceId.value
    if (runtimeStatus.value === 'live' && id) reload(id)
  })
  return { activeProjectId, reset: () => { activeProjectId.value = '' } }
}
