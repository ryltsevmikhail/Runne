import { open } from '@tauri-apps/plugin-dialog'

import { openLocalProject, type Project } from '@/entities/project'

type SelectDirectory = () => Promise<string | null>
type PersistProject = (path: string) => Promise<Project>

async function selectDirectory(): Promise<string | null> {
  const selection = await open({
    directory: true,
    multiple: false,
    title: 'Open local project',
  })
  return typeof selection === 'string' ? selection : null
}

export async function selectAndOpenLocalProject(
  select: SelectDirectory = selectDirectory,
  persist: PersistProject = openLocalProject,
): Promise<Project | null> {
  const path = await select()
  if (path === null) {
    return null
  }
  return persist(path)
}
