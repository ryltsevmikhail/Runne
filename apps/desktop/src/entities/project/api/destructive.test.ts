import { afterEach, beforeEach, describe, expect, it } from 'vitest'

import { currentLocale } from '@/shared/i18n'
import { executeCanonicalProjectDestructiveAction } from './destructive'

const projectId = '01890e00-0000-7000-8000-000000000001'

describe('canonical project destructive adapter', () => {
  let previousLocale = currentLocale.value
  beforeEach(() => { previousLocale = currentLocale.value; currentLocale.value = 'en' })
  afterEach(() => { currentLocale.value = previousLocale })

  it('keeps native confirmation and dispatch behind the opaque intent', async () => {
    const commands: string[] = []
    await executeCanonicalProjectDestructiveAction(
      projectId,
      4,
      'archive',
      async invoke => {
        expect(invoke).toBeDefined()
        return 8
      },
      async (command, args) => {
        commands.push(command)
        if (command === 'prepare_destructive_project_action') {
          expect(args).toEqual({
            request: { projectId, expectedVersion: 4, operation: 'archive', rendererGeneration: 8, locale: 'en' },
          })
          return 'a'.repeat(64)
        }
        expect(args).toEqual({ request: { intent: 'a'.repeat(64), rendererGeneration: 8 } })
        return undefined
      },
    )

    expect(commands).toEqual([
      'prepare_destructive_project_action',
      'dispatch_destructive_project_action',
    ])
  })

  it('returns a typed cancellation without dispatching a mutation', async () => {
    const commands: string[] = []
    const outcome = await executeCanonicalProjectDestructiveAction(
      projectId,
      4,
      'delete',
      async () => 8,
      async command => {
        commands.push(command)
        if (command === 'prepare_destructive_project_action') {
          throw { code: 'destructive_action_cancelled' }
        }
        return undefined
      },
    )

    expect(outcome).toBe('cancelled')
    expect(commands).toEqual(['prepare_destructive_project_action'])
  })

  it('rejects malformed identity and version before host IPC', async () => {
    let invoked = false
    await expect(executeCanonicalProjectDestructiveAction('7', 1, 'delete', async () => 1, async () => {
      invoked = true
      return null
    })).rejects.toThrow('Invalid destructive project mutation')
    await expect(executeCanonicalProjectDestructiveAction(projectId, 0, 'delete', async () => 1, async () => {
      invoked = true
      return null
    })).rejects.toThrow('Invalid destructive project mutation')
    expect(invoked).toBe(false)
  })
})
