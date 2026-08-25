import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import type { OperationalTelemetrySnapshot } from '@/shared/api/platform/operational-telemetry'
import type { RuntimeLifecycleStatus } from '@/shared/api/platform/bootstrap'

import DiagnosticsPage from './DiagnosticsPage.vue'

function telemetrySnapshot(
  lifecycle: RuntimeLifecycleStatus = 'ready',
  restartOrdinal = 3,
): OperationalTelemetrySnapshot {
  return {
    schemaVersion: 1,
    observedAtUnixSeconds: 10,
    runtime: {
      meta: { observedAtUnixSeconds: 10, freshness: 'unavailable', completeness: 'unavailable' },
      snapshot: null,
    },
    hostLifecycle: {
      meta: { observedAtUnixSeconds: 10, freshness: 'observed_in_current_cycle', completeness: 'complete' },
      runtimeMode: 'bundled',
      current: {
        lifecycle,
        failure: null,
        restartOrdinal,
        runtimeLaunchGeneration: 4,
        observedAtUnixSeconds: 10,
      },
      events: [],
      eventStatus: 'complete_since_app_core_start',
      lastAllocatedSequence: null,
      producerDroppedEventCount: 0,
      producerDropCounterSaturated: false,
      evictedEventCount: 0,
      evictionCounterSaturated: false,
    },
  }
}

const diagnostics = async () => ({
  appVersion: '0.1.0',
  platform: 'macos',
  databaseSchemaVersion: 3,
  databaseGeneration: 4,
  projectCount: 2,
  runtimeMode: 'external_local' as const,
  runtime: 'unconfigured' as const,
  runtimeLifecycle: 'external' as const,
  runtimeFailure: null,
})

describe('diagnostics page', () => {
  it('renders only the bounded redacted snapshot', async () => {
    const wrapper = mount(DiagnosticsPage, {
      props: {
        loadDiagnostics: async () => ({
          appVersion: '0.1.0',
          platform: 'macos',
          databaseSchemaVersion: 3,
          databaseGeneration: 4,
          projectCount: 2,
          runtimeMode: 'external_local',
          runtime: 'unconfigured',
          runtimeLifecycle: 'external',
          runtimeFailure: null,
        }),
      },
    })
    await flushPromises()

    expect(wrapper.text()).toContain('Database generation')
    expect(wrapper.text()).toContain('4')
    expect(wrapper.text()).toContain('External runtime')
    expect(wrapper.text()).not.toContain('/Users/')
    expect(wrapper.text()).not.toContain('prompt')
  })

  it('shows a stable failure state without raw error details', async () => {
    const wrapper = mount(DiagnosticsPage, {
      props: {
        loadDiagnostics: async () => {
          throw new Error('/Users/private/token=secret')
        },
      },
    })
    await flushPromises()

    expect(wrapper.get('[role="alert"]').text()).toContain('Diagnostics unavailable')
    expect(wrapper.text()).not.toContain('/Users/private')
    expect(wrapper.text()).not.toContain('secret')
  })

  it('renders runtime and host lifecycle from a validated snapshot', async () => {
    const wrapper = mount(DiagnosticsPage, {
      props: { loadDiagnostics: diagnostics, loadOperationalTelemetry: async () => telemetrySnapshot() },
    })
    await flushPromises()

    expect(wrapper.text()).toContain('Runtime telemetry unavailable')
    expect(wrapper.text()).toContain('Host lifecycle')
    expect(wrapper.text()).toContain('ready')
    expect(wrapper.text()).toContain('3')
    expect(wrapper.text()).toContain('4')
  })

  it('shows unavailable when the initial telemetry request fails', async () => {
    const wrapper = mount(DiagnosticsPage, {
      props: { loadDiagnostics: diagnostics, loadOperationalTelemetry: async () => { throw new Error('token=secret') } },
    })
    await flushPromises()

    expect(wrapper.get('[role="alert"]').text()).toContain('Operational telemetry unavailable')
    expect(wrapper.text()).not.toContain('secret')
  })

  it('keeps confirmed telemetry visible and marks it stale after refresh fails', async () => {
    let attempt = 0
    const wrapper = mount(DiagnosticsPage, {
      props: {
        loadDiagnostics: diagnostics,
        loadOperationalTelemetry: async () => {
          attempt += 1
          if (attempt === 1) return telemetrySnapshot('ready', 7)
          throw new Error('unavailable')
        },
      },
    })
    await flushPromises()
    await wrapper.get('button').trigger('click')
    await flushPromises()

    expect(wrapper.text()).toContain('7')
    expect(wrapper.get('[role="status"]').text()).toContain('Telemetry may be stale')
  })

  it('replaces stale telemetry only after a later valid refresh', async () => {
    let attempt = 0
    const wrapper = mount(DiagnosticsPage, {
      props: {
        loadDiagnostics: diagnostics,
        loadOperationalTelemetry: async () => {
          attempt += 1
          if (attempt === 1) return telemetrySnapshot('ready', 7)
          if (attempt === 2) throw new Error('unavailable')
          return telemetrySnapshot('restarting', 8)
        },
      },
    })
    await flushPromises()
    await wrapper.get('button').trigger('click')
    await flushPromises()
    await wrapper.get('button').trigger('click')
    await flushPromises()

    expect(wrapper.text()).toContain('restarting')
    expect(wrapper.text()).toContain('8')
    expect(wrapper.find('[role="status"]').exists()).toBe(false)
  })

  it('previews and exports only the bounded redacted report', async () => {
    let exported = 0
    const wrapper = mount(DiagnosticsPage, {
      props: {
        loadDiagnostics: diagnostics,
        loadOperationalTelemetry: async () => telemetrySnapshot(),
        loadExportPreview: async () => ({
          schemaVersion: 1,
          redactionVersion: 1,
          categories: ['application', 'runtime'],
          estimatedBytes: 512,
        }),
        exportReport: async () => {
          exported += 1
          return { status: 'saved' as const }
        },
      },
    })
    await flushPromises()
    await wrapper.get('[data-testid="export-diagnostics"]').trigger('click')
    await flushPromises()

    expect(exported).toBe(1)
    expect(wrapper.get('[role="status"]').text()).toContain('saved')
  })

  it('fails closed when the export preview is too large', async () => {
    const wrapper = mount(DiagnosticsPage, {
      props: {
        loadDiagnostics: diagnostics,
        loadOperationalTelemetry: async () => telemetrySnapshot(),
        loadExportPreview: async () => ({
          schemaVersion: 1,
          redactionVersion: 1,
          categories: ['application', 'runtime'],
          estimatedBytes: 131_073,
        }),
        exportReport: async () => ({ status: 'saved' as const }),
      },
    })
    await flushPromises()
    await wrapper.get('[data-testid="export-diagnostics"]').trigger('click')
    await flushPromises()

    expect(wrapper.get('[role="alert"]').text()).toContain('Diagnostics export unavailable')
  })
})
