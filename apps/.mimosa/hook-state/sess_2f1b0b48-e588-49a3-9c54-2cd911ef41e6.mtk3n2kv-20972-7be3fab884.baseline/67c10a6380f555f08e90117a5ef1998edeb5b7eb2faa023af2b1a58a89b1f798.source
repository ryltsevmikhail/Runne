import { describe, expect, it } from 'vitest'

import { syncNotifications } from './notifications'

describe('native notification synchronization', () => {
  it('accepts only bounded aggregate metadata', async () => {
    await expect(syncNotifications(async () => ({ shown: 1, pending: 2 }))).resolves.toEqual({ shown: 1, pending: 2 })
  })

  it('rejects malformed or secret-bearing responses', async () => {
    await expect(syncNotifications(async () => ({ shown: -1, pending: 0 }))).rejects.toThrow()
    await expect(syncNotifications(async () => ({ shown: 0, pending: 0, approvalId: 'secret' }))).rejects.toThrow()
  })
})
