import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { defineComponent, h, nextTick, onBeforeUnmount, ref, shallowRef, type Component, type Ref } from 'vue'
import { describe, expect, it, vi } from 'vitest'

import { provideRuntimeSession, type RuntimeSessionContext, type RuntimeSessionSnapshot } from '@/app/providers/runtime-session'
import type { CanonicalWorkspace } from '@/entities/project'
import { RetryableWorkspaceOpen } from '@/features/open-local-project'
import type { WorkspaceRefreshLoaders } from '../model/workspace-refresh'
import WorkspacePage from './WorkspacePage.vue'

const project = {
  projectId: '01890e00-0000-7000-8000-000000000001',
  workspaceId: '01890e00-0000-7000-8000-000000000002',
  displayName: 'gocode-ui',
  version: 1,
  open: true,
} as const

const projectA = project
const projectB = {
  ...project,
  workspaceId: '01890e00-0000-7000-8000-000000000003',
  displayName: 'runne-cli',
} as const
const WORKSPACE_A = projectA.workspaceId
const WORKSPACE_B = projectB.workspaceId

type Loaders = WorkspaceRefreshLoaders
type LoaderOverrides = Partial<Loaders> & Pick<Loaders, 'loadProject'>

const emptyFiles: Loaders['loadFiles'] = async () => ({ items: [] })
const emptyChanges: Loaders['loadChanges'] = async () => ({ items: [] })
const emptyDiff: Loaders['loadDiff'] = async () => ({ path: '', kind: 'modified', hunks: [], truncated: false })

let unmountedWorkspaceIds: string[] = []

const DraftChatStub = defineComponent({
  props: {
    workspaceId: { type: String, required: true },
    disabled: { type: Boolean, default: false },
  },
  setup(props) {
    const draft = ref('')
    onBeforeUnmount(() => { unmountedWorkspaceIds.push(props.workspaceId) })
    return { draft, props }
  },
  template: '<div data-chat :data-workspace-id="props.workspaceId"><input data-chat-input v-model="draft" :disabled="props.disabled"></div>',
})

const ReconnectStub = defineComponent({
  props: {
    workspaceId: { type: String, required: true },
    viewGeneration: { type: Number, required: true },
    disabled: { type: Boolean, required: true },
    pending: { type: Object, default: null },
  },
  template: '<div data-reconnect></div>',
})

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>(value => { resolve = value })
  return { promise, resolve }
}

function retryableWorkspace(workspaceId = WORKSPACE_A) {
  return new RetryableWorkspaceOpen({
    workspaceId, prepared: 'b'.repeat(64), requestId: 'request-1', rendererGeneration: 7,
  }, async () => ({ reference: 'b'.repeat(64), summary: { displayName: 'Selected folder' } }))
}

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
  loaders: LoaderOverrides,
  runtime = mutableRuntimeContext(),
  stubs: Record<string, Component> = {},
  initialWorkspaceId = WORKSPACE_A,
) {
  const props: Loaders = {
    loadProject: loaders.loadProject,
    loadFiles: loaders.loadFiles ?? emptyFiles,
    loadChanges: loaders.loadChanges ?? emptyChanges,
    loadDiff: loaders.loadDiff ?? emptyDiff,
  }
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/', component: { template: '<div>Projects</div>' } },
      { path: '/projects/:projectId', name: 'project-details', component: { template: '<div>Project details</div>' } },
      { path: '/workspaces/:workspaceId', name: 'workspace', component: WorkspacePage },
    ],
  })
  await router.push(`/workspaces/${initialWorkspaceId}`)
  await router.isReady()
  const Harness = defineComponent({
    setup() {
      provideRuntimeSession(runtime.context)
      return () => h(WorkspacePage, props)
    },
  })
  const wrapper = mount(Harness, { global: { plugins: [router], stubs } })
  await flushPromises()
  return { wrapper, router, runtime }
}

describe('workspace page lifecycle', () => {
  it('keeps the same chat element and draft during same-id refresh and runtime transient', async () => {
    unmountedWorkspaceIds = []
    const second = deferred<typeof projectA>()
    let calls = 0
    const loadProject = vi.fn(async (): Promise<CanonicalWorkspace> => (
      ++calls === 1 ? projectA : second.promise
    ))
    const runtime = mutableRuntimeContext()
    const { wrapper } = await mountPageWith({ loadProject }, runtime, { ConversationChat: DraftChatStub })
    const chatElement = wrapper.get('[data-chat]').element
    await wrapper.get('[data-chat-input]').setValue('keep this draft')
    runtime.set({ runtime: 'reconnecting', status: 'reconnecting', canMutate: false })
    await nextTick()
    expect((wrapper.get('[data-chat-input]').element as HTMLInputElement).value).toBe('keep this draft')
    expect(wrapper.get('[data-chat-input]').attributes('disabled')).toBeDefined()
    expect(wrapper.get('[data-chat]').element).toBe(chatElement)
    runtime.set({ runtime: 'live', status: 'live', canMutate: true })
    await nextTick()
    expect(loadProject).toHaveBeenCalledTimes(2)
    expect(wrapper.get('[data-chat]').element).toBe(chatElement)
    second.resolve(projectA)
    await flushPromises()
    expect((wrapper.get('[data-chat-input]').element as HTMLInputElement).value).toBe('keep this draft')
    expect(wrapper.get('[data-chat]').element).toBe(chatElement)
  })

  it('unmounts chat A and creates an empty chat for workspace B', async () => {
    unmountedWorkspaceIds = []
    const runtime = mutableRuntimeContext()
    const { wrapper, router } = await mountPageWith({
      loadProject: async id => id === WORKSPACE_A ? projectA : projectB,
    }, runtime, { ConversationChat: DraftChatStub })
    const chatA = wrapper.get('[data-chat]').element
    await wrapper.get('[data-chat-input]').setValue('draft-A')
    await router.push(`/workspaces/${WORKSPACE_B}`)
    await flushPromises()
    expect(wrapper.get('[data-chat]').element).not.toBe(chatA)
    expect(wrapper.get('[data-chat]').attributes('data-workspace-id')).toBe(WORKSPACE_B)
    expect((wrapper.get('[data-chat-input]').element as HTMLInputElement).value).toBe('')
    expect(unmountedWorkspaceIds).toContain(WORKSPACE_A)
  })

  it('keeps a parent-owned reconnect attempt across runtime status changes', async () => {
    unmountedWorkspaceIds = []
    const runtime = mutableRuntimeContext()
    const { wrapper } = await mountPageWith({
      loadProject: async () => projectA,
      loadFiles: async () => { throw new Error('files unavailable') },
    }, runtime, { ConversationChat: DraftChatStub, WorkspaceFolderReconnect: ReconnectStub })
    const attempt = retryableWorkspace()
    await wrapper.get('[data-chat-input]').setValue('draft survives')
    wrapper.findComponent(ReconnectStub).vm.$emit('retryable', attempt, WORKSPACE_A, 0)
    await nextTick()
    expect(wrapper.findComponent(ReconnectStub).props('pending')).toBe(attempt)
    runtime.set({ status: 'loading', canMutate: false })
    await nextTick()
    expect(wrapper.findComponent(ReconnectStub).props('pending')).toBe(attempt)
    expect((wrapper.get('[data-chat-input]').element as HTMLInputElement).value).toBe('draft survives')
    expect(wrapper.get('[data-chat-input]').attributes('disabled')).toBeDefined()
    runtime.set({ runtime: 'live', status: 'live', canMutate: true })
    await flushPromises()
    expect(wrapper.findComponent(ReconnectStub).props('pending')).toBe(attempt)
    expect((wrapper.get('[data-chat-input]').element as HTMLInputElement).value).toBe('draft survives')
  })

  it('ignores a stale reconnect completion after routing from A to B', async () => {
    const loadProject = vi.fn(async (id: string) => id === WORKSPACE_A ? projectA : projectB)
    const runtime = mutableRuntimeContext()
    const { wrapper, router } = await mountPageWith({
      loadProject,
      loadFiles: async () => { throw new Error('files unavailable') },
    }, runtime, { WorkspaceFolderReconnect: ReconnectStub })
    const reconnect = wrapper.findComponent(ReconnectStub)
    const generation = reconnect.props('viewGeneration') as number
    await router.push(`/workspaces/${WORKSPACE_B}`)
    await flushPromises()
    reconnect.vm.$emit('connected', WORKSPACE_A, generation)
    await flushPromises()
    expect(wrapper.get('h1').text()).toBe(projectB.displayName)
    // The stale reconnect completion is ignored (the bounded file retry is
    // scheduled on a timer and not observed here).
    expect(loadProject.mock.calls.filter(([id]) => id === WORKSPACE_B)).toHaveLength(1)
  })
})
