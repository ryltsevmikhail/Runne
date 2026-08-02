import { describe, expect, it } from 'vitest'

import { connectRuntime, loadBootstrap, saveTheme } from './bootstrap'

describe('bootstrap IPC adapter', () => {
  it('accepts the closed sanitized bootstrap response', async () => {
    const state = await loadBootstrap(async () => ({
      theme: 'light',
      runtimeMode: 'external_local',
      runtime: 'unconfigured',
      runtimeLifecycle: 'external',
      runtimeFailure: null,
    }))

    expect(state).toEqual({
      theme: 'light',
      runtimeMode: 'external_local',
      runtime: 'unconfigured',
      runtimeLifecycle: 'external',
      runtimeFailure: null,
    })
  })

  it('rejects an unknown runtime availability', async () => {
    await expect(
      loadBootstrap(async () => ({
        theme: 'dark',
        runtimeMode: 'external_local',
        runtime: 'connected',
        runtimeLifecycle: 'external',
        runtimeFailure: null,
      })),
    ).rejects.toThrow('Invalid bootstrap response')
  })

  it('rejects an unknown runtime mode', async () => {
    await expect(
      loadBootstrap(async () => ({
        theme: 'dark',
        runtimeMode: 'managed',
        runtime: 'unconfigured',
        runtimeLifecycle: 'external',
        runtimeFailure: null,
      })),
    ).rejects.toThrow('Invalid bootstrap response')
  })

  it('accepts only the closed lifecycle and safe failure vocabularies', async () => {
    const lifecycle = [
      'configuration_required',
      'starting',
      'ready',
      'restarting',
      'degraded',
      'failed',
      'external',
    ] as const
    for (const runtimeLifecycle of lifecycle) {
      await expect(loadBootstrap(async () => ({
        theme: 'dark',
        runtimeMode: 'bundled',
        runtime: 'reconnecting',
        runtimeLifecycle,
        runtimeFailure: null,
      }))).resolves.toMatchObject({ runtimeLifecycle })
    }

    const failures = [
      'protected_activation_unavailable',
      'bundled_executable_unavailable',
      'bundled_executable_identity_mismatch',
      'protected_readiness_rejected',
      'bundled_restart_exhausted',
      'bundled_shutdown_incomplete',
      'unsupported_platform_backend',
      'downgraded_external_profile',
    ] as const
    for (const runtimeFailure of failures) {
      await expect(loadBootstrap(async () => ({
        theme: 'dark',
        runtimeMode: 'bundled',
        runtime: 'fatal',
        runtimeLifecycle: 'failed',
        runtimeFailure,
      }))).resolves.toMatchObject({ runtimeFailure })
    }

    await expect(loadBootstrap(async () => ({
      theme: 'dark',
      runtimeMode: 'bundled',
      runtime: 'unconfigured',
      runtimeLifecycle: 'configuration_required',
      runtimeFailure: 'configuration_required',
    }))).resolves.toMatchObject({
      runtimeLifecycle: 'configuration_required',
      runtimeFailure: 'configuration_required',
    })

    await expect(loadBootstrap(async () => ({
      theme: 'dark',
      runtimeMode: 'bundled',
      runtime: 'fatal',
      runtimeLifecycle: 'compromised',
      runtimeFailure: '/private/token',
    }))).rejects.toThrow('Invalid bootstrap response')
  })

  it('sends a typed theme update without other settings', async () => {
    const calls: Array<[string, Record<string, unknown> | undefined]> = []

    await saveTheme('light', async (command, args) => {
      calls.push([command, args])
    })

    expect(calls).toEqual([['set_theme', { theme: 'light' }]])
  })

  it('accepts only a closed runtime state from the host connection command', async () => {
    const calls: string[] = []
    const state = await connectRuntime(async (command) => {
      calls.push(command)
      return 'live'
    })

    expect(state).toBe('live')
    expect(calls).toEqual(['connect_runtime'])

    await expect(connectRuntime(async () => 'connected')).rejects.toThrow(
      'Invalid runtime connection response',
    )
  })

  it('accepts exactly the proof-gated runtime connection states', async () => {
    const states = [
      'unconfigured',
      'profile_loaded',
      'peer_verified',
      'bootstrap_proved',
      'authenticated',
      'reconciling',
      'live',
      'reconnecting',
      'incompatible',
      'revoked',
      'resync_required',
      'fatal',
    ] as const

    for (const state of states) {
      await expect(connectRuntime(async () => state)).resolves.toBe(state)
    }

    for (const state of ['connecting', 'authenticating', 'stale']) {
      await expect(connectRuntime(async () => state)).rejects.toThrow(
        'Invalid runtime connection response',
      )
    }
  })
})
