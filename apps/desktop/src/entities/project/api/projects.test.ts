import { describe, expect, it } from 'vitest'

import {
  acquireRendererGeneration,
  getProject,
  listProjects,
  prepareSelectedWorkspace,
  openSelectedWorkspace,
  retryOpenSelectedWorkspace,
  requestDirectorySelection,
} from './projects'

const project = {
  projectId: '01890e00-0000-7000-8000-000000000001',
  workspaceId: '01890e00-0000-7000-8000-000000000002',
  displayName: 'gocode-ui',
  lastOpenedAt: 1_753_500_000_000,
} as const

describe('project IPC adapter', () => {
  it('accepts a closed project list response', async () => {
    const projects = await listProjects(async () => [project])

    expect(projects).toEqual([project])
  })

  it('requests an opaque host-owned directory selection', async () => {
    const calls: Array<[string, Record<string, unknown> | undefined]> = []
    const reference = 'a'.repeat(64)

    const selection = await requestDirectorySelection('request-1', 0, async (command, args) => {
      calls.push([command, args])
      return { reference }
    })

    expect(selection).toEqual({ reference })
    expect(calls).toEqual([
      ['request_directory_selection', { requestId: 'request-1', rendererGeneration: 0 }],
    ])
  })

  it('accepts only the redacted prepared workspace response', async () => {
    const calls: Array<[string, Record<string, unknown> | undefined]> = []
    const request = {
      selection: 'a'.repeat(64),
      rendererGeneration: 7,
      requestId: 'request-1',
      workspaceId: '01890e00-0000-7000-8000-000000000001',
      expectedVersion: 3,
    }
    const prepared = await prepareSelectedWorkspace(request, async (command, args) => {
      calls.push([command, args === undefined ? undefined : structuredClone(args)])
      return { reference: 'b'.repeat(64), summary: { displayName: 'Selected folder' } }
    })

    expect(prepared.summary.displayName).toBe('Selected folder')
    expect(calls).toEqual([
      ['prepare_selected_workspace', { request: {
        selection: 'a'.repeat(64),
        rendererGeneration: 7,
        requestId: 'request-1',
        workspaceId: '01890e00-0000-7000-8000-000000000001',
        expectedVersion: 3,
      } }],
    ])
  })

  it('opens only the host-issued prepared workspace reference', async () => {
    const calls: Array<[string, Record<string, unknown> | undefined]> = []
    const request = {
      prepared: 'b'.repeat(64),
      rendererGeneration: 4,
      requestId: 'request-1',
    }
    await openSelectedWorkspace(request, async (command, args) => {
      calls.push([command, args === undefined ? undefined : structuredClone(args)])
      return undefined
    })

    expect(calls).toEqual([
      ['open_selected_workspace', { request: {
        prepared: 'b'.repeat(64),
        rendererGeneration: 4,
        requestId: 'request-1',
      } }],
    ])
  })

  it('sends retry with the exact original prepared request shape', async () => {
    const calls: Array<[string, Record<string, unknown> | undefined]> = []
    const request = {
      prepared: 'b'.repeat(64),
      requestId: 'request-1',
      rendererGeneration: 7,
    }

    await retryOpenSelectedWorkspace(request, async (command, args) => {
      calls.push([command, args === undefined ? undefined : structuredClone(args)])
      return undefined
    })

    expect(request).toEqual({
      prepared: 'b'.repeat(64),
      requestId: 'request-1',
      rendererGeneration: 7,
    })
    expect(calls).toEqual([
      ['retry_open_selected_workspace', { request: {
        prepared: 'b'.repeat(64),
        rendererGeneration: 7,
        requestId: 'request-1',
      } }],
    ])
  })

  it('rejects malformed host generations and prepared path leaks', async () => {
    await expect(acquireRendererGeneration(async () => '7')).rejects.toThrow(
      'Invalid renderer generation response',
    )
    await expect(prepareSelectedWorkspace({
      selection: 'a'.repeat(64), rendererGeneration: 7, requestId: 'request-1',
      workspaceId: '01890e00-0000-7000-8000-000000000001', expectedVersion: 3,
    }, async () => ({
      reference: 'b'.repeat(64), summary: { displayName: 'Selected folder', path: '/private' },
    }))).rejects.toThrow('Invalid prepared workspace response')
  })

  it('rejects malformed project data at the renderer boundary', async () => {
    await expect(
      getProject(project.projectId, async () => ({
        ...project,
        workspaceId: '7',
      })),
    ).rejects.toThrow('Invalid project response')
  })

  it('rejects numeric IDs and raw paths at the renderer boundary', async () => {
    await expect(getProject('7', async () => null)).rejects.toThrow('Invalid project identifier')
    await expect(listProjects(async () => [{ ...project, path: '/private/root' }])).rejects.toThrow(
      'Invalid projects response',
    )
  })
})
