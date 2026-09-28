import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { defineComponent, h, shallowRef, type Ref } from 'vue'
import { markProjectTrustChanged, type CanonicalWorkspace } from '@/entities/project'
import { describe, expect, it, vi } from 'vitest'

import { provideRuntimeSession, type RuntimeSessionContext, type RuntimeSessionSnapshot } from '@/app/providers/runtime-session'
import { createSingleFlightLoader } from '../model/workspace-retry'
import type { WorkspaceRefreshLoaders } from '../model/workspace-refresh'
import WorkspacePage from './WorkspacePage.vue'

const projectA = {
  projectId: '01890e00-0000-7000-8000-000000000001',
  workspaceId: '01890e00-0000-7000-8000-000000000002',
  displayName: 'gocode-ui',
  version: 1,
  open: true,
} as const
const WORKSPACE_A = projectA.workspaceId
const projectB = {
  ...projectA,
  workspaceId: '01890e00-0000-7000-8000-000000000003',
  displayName: 'runne-cli',
} as const
const WORKSPACE_B = projectB.workspaceId

function mutableRuntimeContext() {
  const snapshot = shallowRef<RuntimeSessionSnapshot>({
    runtime: 'live', status: 'live', canMutate: true,
  })
  const context: RuntimeSessionContext = {
    snapshot: snapshot as Readonly<Ref<RuntimeSessionSnapshot>>,
    connect: async () => snapshot.value,
    retry: async () => snapshot.value,
    close: async () => {},
    observeBootstrap: () => snapshot.value,
    sessionTicket: () => 0,
    ticketFenced: () => false,
  }
  return {
    context,
    set(next: Partial<RuntimeSessionSnapshot>) {
      snapshot.value = { ...snapshot.value, ...next }
    },
  }
}

async function mountPageWith(
  loaders: Partial<WorkspaceRefreshLoaders> & Pick<WorkspaceRefreshLoaders, 'loadProject'>,
  runtime = mutableRuntimeContext(),
) {
  const props: WorkspaceRefreshLoaders = {
    loadProject: loaders.loadProject,
    loadFiles: loaders.loadFiles ?? (async () => ({ items: [] })),
    loadChanges: loaders.loadChanges ?? (async () => ({ items: [] })),
    loadDiff: loaders.loadDiff ?? (async () => ({ path: '', kind: 'modified' as const, hunks: [], truncated: false })),
  }
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/', component: { template: '<div>Projects</div>' } },
      { path: '/projects/:projectId', name: 'project-details', component: { template: '<div>Project details</div>' } },
      { path: '/workspaces/:workspaceId', name: 'workspace', component: WorkspacePage },
    ],
  })
  await router.push(`/workspaces/${WORKSPACE_A}`)
  await router.isReady()
  const Harness = defineComponent({
    setup() {
      provideRuntimeSession(runtime.context)
      return () => h(WorkspacePage, props)
    },
  })
  const wrapper = mount(Harness, { global: { plugins: [router] } })
  await flushPromises()
  return { wrapper, router, runtime }
}

describe('workspace page bounded file retry', () => {
  it('clears revoked workspace files and diffs, then reloads the selected project', async () => {
    let fileLoad = 0
    let changeLoad = 0
    const { wrapper } = await mountPageWith({
      loadProject: async () => projectA,
      loadFiles: async () => ({ items: ++fileLoad === 1 ? [{ path: 'before.txt', kind: 'file' as const, sizeBytes: 1 }] : [] }),
      loadChanges: async () => ({ items: ++changeLoad === 1 ? [{ path: 'before.txt', kind: 'modified' as const, additions: 0, deletions: 0 }] : [] }),
      loadDiff: async () => ({ path: 'before.txt', kind: 'modified' as const, hunks: [], truncated: false }),
    })
    expect(wrapper.text()).toContain('before.txt')

    markProjectTrustChanged(projectA.projectId)
    await flushPromises()
    expect(fileLoad).toBe(2)
    expect(changeLoad).toBe(2)
    expect(wrapper.text()).not.toContain('before.txt')
  })

  it('discards a pre-trust file response and performs a fresh read after trust changes', async () => {
    let releaseOld!: (value: { items: readonly { path: string; kind: 'file'; sizeBytes: number }[] }) => void
    let fileLoad = 0
    const { wrapper } = await mountPageWith({
      loadProject: async () => projectA,
      loadFiles: async () => {
        fileLoad += 1
        if (fileLoad === 1) return new Promise(resolve => { releaseOld = resolve })
        return { items: [{ path: 'after.txt', kind: 'file' as const, sizeBytes: 1 }] }
      },
    })
    markProjectTrustChanged(projectA.projectId)
    releaseOld({ items: [{ path: 'before.txt', kind: 'file', sizeBytes: 1 }] })
    await flushPromises()
    expect(fileLoad).toBe(2)
    expect(wrapper.text()).toContain('after.txt')
    expect(wrapper.text()).not.toContain('before.txt')
  })

  it('retries a failed file load once while the session stays live', async () => {
    vi.useFakeTimers()
    try {
      const loadFiles = vi.fn(async () => {
        throw new Error('root not admitted yet')
      })
      await mountPageWith(
        { loadProject: async () => projectA, loadFiles },
        mutableRuntimeContext(),
      )
      expect(loadFiles).toHaveBeenCalledTimes(1)
      await vi.advanceTimersByTimeAsync(2500)
      await flushPromises()
      // Exactly one bounded retry; no stacking afterwards.
      expect(loadFiles).toHaveBeenCalledTimes(2)
      await vi.advanceTimersByTimeAsync(10_000)
      await flushPromises()
      expect(loadFiles).toHaveBeenCalledTimes(2)
    }
    finally {
      vi.useRealTimers()
    }
  })

  it('re-arms the bounded file retry after a runtime lifecycle change', async () => {
    vi.useFakeTimers()
    try {
      const runtime = mutableRuntimeContext()
      const loadFiles = vi.fn(async () => {
        throw new Error('root never admitted')
      })
      const { runtime: lifecycle } = await mountPageWith(
        { loadProject: async () => projectA, loadFiles },
        runtime,
      )
      expect(loadFiles).toHaveBeenCalledTimes(1)
      await vi.advanceTimersByTimeAsync(2500)
      await flushPromises()
      expect(loadFiles).toHaveBeenCalledTimes(2)
      await vi.advanceTimersByTimeAsync(10_000)
      await flushPromises()
      expect(loadFiles).toHaveBeenCalledTimes(2)

      // A reconnect/live cycle is a new generation: exactly one retry again.
      lifecycle.set({ runtime: 'reconnecting', status: 'reconnecting', canMutate: false })
      await flushPromises()
      lifecycle.set({ runtime: 'live', status: 'live', canMutate: true })
      await flushPromises()
      expect(loadFiles).toHaveBeenCalledTimes(3)
      await vi.advanceTimersByTimeAsync(2500)
      await flushPromises()
      expect(loadFiles).toHaveBeenCalledTimes(4)
      await vi.advanceTimersByTimeAsync(10_000)
      await flushPromises()
      expect(loadFiles).toHaveBeenCalledTimes(4)
    }
    finally {
      vi.useRealTimers()
    }
  })

  it('keeps at most two parallel loads and drains only the latest pending id', async () => {
    vi.useFakeTimers()
    try {
      let fileCalls = 0
      const release: Record<string, () => void> = {}
      const loadProject = vi.fn((id: string): Promise<CanonicalWorkspace> => {
        if (id === WORKSPACE_A || id === WORKSPACE_B) {
          return new Promise<typeof projectA | typeof projectB>(resolve => {
            release[id] = () => resolve(id === WORKSPACE_A ? projectA : projectB)
          })
        }
        return Promise.resolve({ ...projectA, workspaceId: id, displayName: 'latest' })
      })
      const loadFiles = vi.fn(async () => {
        fileCalls += 1
        throw new Error('files unavailable')
      })
      const { wrapper, router } = await mountPageWith(
        { loadProject, loadFiles },
        mutableRuntimeContext(),
      )
      expect(fileCalls).toBe(0)

      // A hangs (slot 1) -> B hangs (slot 2) -> C: the slots are full, so C
      // coalesces into the latest-only pending id (no third parallel load).
      await router.push(`/workspaces/${WORKSPACE_B}`)
      await flushPromises()
      await router.push('/workspaces/01890e00-0000-7000-8000-000000000004')
      await flushPromises()
      await vi.advanceTimersByTimeAsync(10_000)
      await flushPromises()
      expect(fileCalls).toBe(0)

      // Releasing B drains the latest pending C: its files fail and exactly
      // one bounded retry follows — then the count stops growing.
      release[WORKSPACE_B]?.()
      await flushPromises()
      expect(fileCalls).toBe(1)
      await vi.advanceTimersByTimeAsync(2500)
      await flushPromises()
      expect(fileCalls).toBe(2)
      await vi.advanceTimersByTimeAsync(10_000)
      await flushPromises()
      expect(fileCalls).toBe(2)
      expect(wrapper.get('h1').text()).toBe('latest')
    }
    finally {
      vi.useRealTimers()
    }
  })

  it('never runs a duplicate id in a second parallel slot', async () => {
    const calls: string[] = []
    const release: Record<string, () => void> = {}
    const loader = createSingleFlightLoader(
      id => new Promise<void>(resolve => { calls.push(id); release[id] = resolve }),
      () => true,
    )
    loader.request(WORKSPACE_A)
    // A duplicate of the still-hanging A coalesces instead of occupying the
    // second slot, so an unrelated B can still start immediately.
    loader.request(WORKSPACE_A)
    loader.request(WORKSPACE_B)
    expect(calls).toEqual([WORKSPACE_A, WORKSPACE_B])
    release[WORKSPACE_B]?.()
    await Promise.resolve()
    await Promise.resolve()
    // Draining waits for the still-active A; the pending duplicate survives.
    expect(calls).toEqual([WORKSPACE_A, WORKSPACE_B])
    release[WORKSPACE_A]?.()
    await flushPromises()
    expect(calls).toEqual([WORKSPACE_A, WORKSPACE_B, WORKSPACE_A])
    loader.dispose()
  })
})
