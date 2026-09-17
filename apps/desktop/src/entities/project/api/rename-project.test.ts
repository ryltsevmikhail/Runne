import { describe, expect, it, vi } from 'vitest'
import { projectsRevision, renameCanonicalProject } from './canonical-projects'

const id = '01890e00-0000-7000-8000-000000000001'
describe('canonical project rename', () => {
  it('sends the expected version and invalidates the list only after a valid acknowledgement', async () => {
    const revision = projectsRevision.value
    const invoke = vi.fn(async () => ({ projectId: id, newVersion: 4 }))
    await renameCanonicalProject(id, 3, 'New name', invoke)
    expect(invoke).toHaveBeenCalledWith('rename_runtime_project', { request: { projectId: id, expectedVersion: 3, displayName: 'New name' } })
    expect(projectsRevision.value).toBe(revision + 1)
  })
  it('rejects invalid names and mismatched acknowledgements without invalidating the list', async () => {
    const revision = projectsRevision.value
    const invoke = vi.fn(async () => ({ projectId: id, newVersion: 3 }))
    for (const name of ['', '  ', 'a\nb', 'a'.repeat(257)]) {
      await expect(renameCanonicalProject(id, 3, name, invoke)).rejects.toThrow()
    }
    expect(invoke).not.toHaveBeenCalled()
    await expect(renameCanonicalProject(id, 3, 'Valid', invoke)).rejects.toThrow()
    expect(projectsRevision.value).toBe(revision)
  })
})
