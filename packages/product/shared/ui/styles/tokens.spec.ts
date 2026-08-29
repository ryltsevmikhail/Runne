import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const tokensCss = await readFile(resolve(process.cwd(), 'shared/ui/styles/tokens.css'), 'utf8')

describe('CSS tokens', () => {
  it('defines Pen semantic color tokens in the production stylesheet', () => {
    expect(tokensCss).toMatch(/--gocode-canvas:\s*#080808/)
    expect(tokensCss).toMatch(/--gocode-accent:\s*#315CFF/)
    expect(tokensCss).toMatch(/--gocode-warning:\s*#F59E0B/)
  })

  it('defines spacing and typography tokens in the production stylesheet', () => {
    expect(tokensCss).toMatch(/--gocode-space-md:\s*12px/)
    expect(tokensCss).toMatch(/--gocode-space-xl:\s*24px/)
    expect(tokensCss).toMatch(/--gocode-font-ui:.*Space Grotesk/)
  })

  it('overrides semantic UI tokens for the light theme', () => {
    expect(tokensCss).toMatch(/\[data-theme='light'\][\s\S]*--gocode-canvas:\s*#E7EAEE/)
    expect(tokensCss).toMatch(/\[data-theme='light'\][\s\S]*--gocode-sidebar:\s*#ECEFF2/)
    expect(tokensCss).toMatch(/\[data-theme='light'\][\s\S]*--gocode-text-primary:\s*#151820/)
  })
})
