import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const [badgeCss, workspacePanelCss] = await Promise.all([
  readFile(resolve(process.cwd(), 'shared/ui/gc-badge/GcBadge.vue'), 'utf8'),
  readFile(resolve(process.cwd(), 'shared/ui/gc-workspace-panel/GcWorkspacePanel.vue'), 'utf8'),
])

describe('component motion', () => {
  it('disables infinite decorative animations for reduced motion', () => {
    expect(badgeCss).toMatch(/@media \(prefers-reduced-motion: reduce\)[\s\S]*animation: none/)
    expect(workspacePanelCss).toMatch(/@media \(prefers-reduced-motion: reduce\)[\s\S]*animation: none/)
  })
})
