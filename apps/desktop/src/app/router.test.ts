import { describe, expect, it } from 'vitest'
import { createMemoryHistory, createRouter, isNavigationFailure, NavigationFailureType, parseQuery, stringifyQuery } from 'vue-router'
import type { NavigationFailure, RouteLocationRaw } from 'vue-router'

import { routes } from './router'

const canonicalId = '01890e00-0000-7000-8000-000000000002'
const makeRouter = () => createRouter({ history: createMemoryHistory(), routes })

describe('ordinary routing compatibility at desktop boundaries', () => {
  it('round-trips canonical workspace params and scalar, repeated, null and empty queries', async () => {
    const router = makeRouter()
    const target: RouteLocationRaw = {
      name: 'workspace', params: { workspaceId: canonicalId },
      query: { processId: canonicalId, text: '雪 +%/?#', repeated: ['one', 'two'], flag: null, empty: '' },
      hash: '#details',
    }
    const resolved = router.resolve(target)
    expect(resolved.href).toBe(`/workspaces/${canonicalId}?processId=${canonicalId}&text=%E9%9B%AA+%2B%25/?%23&repeated=one&repeated=two&flag&empty=#details`)
    const result: NavigationFailure | void | undefined = await router.push(target)
    expect(result).toBeUndefined()
    expect(router.currentRoute.value.params).toEqual({ workspaceId: canonicalId })
    expect(router.currentRoute.value.query).toEqual({ processId: canonicalId, text: '雪 +%/?#', repeated: ['one', 'two'], flag: null, empty: '' })
    expect(router.currentRoute.value.hash).toBe('#details')
    expect(router.resolve(resolved.href).query).toEqual(router.currentRoute.value.query)
  })

  it('preserves ordinary query plus decoding without experimental array normalization', () => {
    expect(parseQuery('text=a+b%2Bc&flag&empty=&key=one&key=two')).toEqual({ text: 'a b+c', flag: null, empty: '', key: ['one', 'two'] })
    expect(stringifyQuery({ text: 'a b+c', flag: null, empty: '', key: ['one', 'two'] })).toBe('text=a+b%2Bc&flag&empty=&key=one&key=two')
    expect(parseQuery('__proto__=inert&constructor=literal&safe=yes').safe).toBe('yes')
    expect(Object.prototype).not.toHaveProperty('safe')
  })

  it('keeps project redirect query replacement and inherited hash, then remains navigable', async () => {
    const router = makeRouter()
    await router.push(`/projects/${canonicalId}?discard=old&project=wrong#details`)
    expect(router.currentRoute.value.name).toBe('projects')
    expect(router.currentRoute.value.fullPath).toBe(`/?project=${canonicalId}#details`)
    expect(router.currentRoute.value.query).toEqual({ project: canonicalId })
    await router.push('/recovery')
    expect(router.currentRoute.value.name).toBe('recovery')
  })

  it('does not promote an encoded noncanonical path value into a canonical identity', () => {
    const router = makeRouter()
    const resolved = router.resolve({ name: 'workspace', params: { workspaceId: 'not/a+canonical%id' } })
    expect(resolved.href).toBe('/workspaces/not%2Fa+canonical%25id')
    expect(router.resolve(resolved.href).params.workspaceId).toBe('not/a+canonical%id')
  })

  it('distinguishes abort, duplicate and thrown guard rejection and supports subsequent navigation', async () => {
    const router = makeRouter()
    await router.push('/')
    const remove = router.beforeEach(to => to.name === 'recovery' ? false : true)
    const aborted = await router.push('/recovery')
    expect(isNavigationFailure(aborted, NavigationFailureType.aborted)).toBe(true)
    expect(router.currentRoute.value.name).toBe('projects')
    remove()
    const duplicate = await router.push('/')
    expect(isNavigationFailure(duplicate, NavigationFailureType.duplicated)).toBe(true)
    const failure = new Error('fixture navigation failure')
    const errors: unknown[] = []
    router.onError(error => errors.push(error))
    const removeThrow = router.beforeEach(() => { throw failure })
    await expect(router.push('/recovery')).rejects.toBe(failure)
    expect(errors).toEqual([failure])
    expect(router.currentRoute.value.name).toBe('projects')
    removeThrow()
    await router.push('/recovery')
    expect(router.currentRoute.value.name).toBe('recovery')
  })

  it('settles a deferred cancelled navigation without replacing the winning route', async () => {
    const router = makeRouter()
    await router.push('/')
    let release: () => void = () => {}
    let entered: () => void = () => {}
    const gate = new Promise<void>(resolve => { release = resolve })
    const started = new Promise<void>(resolve => { entered = resolve })
    const remove = router.beforeEach(async to => { if (to.name === 'recovery') { entered(); await gate } })
    const pending = router.push('/recovery')
    await started
    await router.push('/settings')
    release()
    expect(isNavigationFailure(await pending, NavigationFailureType.cancelled)).toBe(true)
    expect(router.currentRoute.value.name).toBe('settings')
    remove()
    await router.replace('/recovery')
    expect(router.currentRoute.value.name).toBe('recovery')
  })
})

describe('desktop routes', () => {
  it('keeps Project and Workspace route parameters distinct', () => {
    const paths = new Map(routes.map((route) => [route.name, route.path]))

    expect(paths.get('project-details')).toBe('/projects/:projectId')
    expect(paths.get('workspace')).toBe('/workspaces/:workspaceId')
  })

  it('exposes a TaskRun route using only the canonical runtime ID', () => {
    const taskRun = routes.find(route => route.name === 'task-run')

    expect(taskRun?.path).toBe('/task-runs/:taskRunId')
  })

  it('keeps the TaskRun inventory separate from the detail route', () => {
    const paths = new Map(routes.map((route) => [route.name, route.path]))

    expect(paths.get('task-run-inventory')).toBe('/task-runs')
    expect(paths.get('task-run')).toBe('/task-runs/:taskRunId')
  })

  it('exposes the standalone fail-closed recovery route', () => {
    const paths = new Map(routes.map((route) => [route.name, route.path]))

    expect(paths.get('recovery')).toBe('/recovery')
  })

  it('exposes the standalone Text chat route without workspace parameters', () => {
    const textChat = routes.find(route => route.name === 'text-chat')

    expect(textChat?.path).toBe('/text-chat')
  })

  it('exposes the owner-bound appearance settings route', () => {
    const appearance = routes.find(route => route.name === 'appearance-settings')

    expect(appearance?.path).toBe('/settings/appearance')
  })

  it('exposes the unavailable runtime configuration target route', () => {
    const paths = new Map(routes.map((route) => [route.name, route.path]))

    expect(paths.get('runtime-configuration')).toBe('/settings/runtime-configuration')
  })

  it('exposes isolated settings routes for local desktop preferences', () => {
    const paths = new Map(routes.map((route) => [route.name, route.path]))

    expect(paths.get('settings')).toBe('/settings')
    expect(paths.get('shortcuts-settings')).toBe('/settings/shortcuts')
    expect(paths.get('providers-settings')).toBe('/settings/providers')
    expect(paths.get('devices-settings')).toBe('/settings/devices')
    expect(paths.get('updates-settings')).toBe('/settings/updates')
  })
})
