import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const tokensCss = await readFile(resolve(process.cwd(), 'shared/ui/styles/tokens.css'), 'utf8')

describe('CSS tokens', () => {
  it('defines Pen semantic color tokens in the production stylesheet', () => {
    expect(tokensCss).toMatch(/--runne-canvas:\s*#111214/)
    expect(tokensCss).toMatch(/--runne-accent:\s*#F47832/)
    expect(tokensCss).toMatch(/--runne-warning:\s*#F59E0B/)
  })

  it('defines spacing and typography tokens in the production stylesheet', () => {
    expect(tokensCss).toMatch(/--runne-space-md:\s*12px/)
    expect(tokensCss).toMatch(/--runne-space-xl:\s*24px/)
    expect(tokensCss).toMatch(/--runne-font-ui:.*Inter/)
  })

  it('overrides semantic UI tokens for the light theme', () => {
    expect(tokensCss).toMatch(/\[data-theme='light'\][\s\S]*--runne-canvas:\s*#E9E9E7/)
    expect(tokensCss).toMatch(/\[data-theme='light'\][\s\S]*--runne-text-primary:\s*#151616/)
  })
})
