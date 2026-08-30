import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const tokensCss = await readFile(resolve(process.cwd(), 'shared/ui/styles/tokens.css'), 'utf8')

describe('CSS tokens', () => {
  it('defines the dark semantic colors from the Pen variables', () => {
    expect(tokensCss).toMatch(/--runne-canvas:\s*#080808/)
    expect(tokensCss).toMatch(/--runne-surface:\s*#111214/)
    expect(tokensCss).toMatch(/--runne-surface-raised:\s*#272A2F/)
    expect(tokensCss).toMatch(/--runne-text-primary:\s*#FFFFFF/)
    expect(tokensCss).toMatch(/--runne-text-secondary:\s*#A7ABB2/)
    expect(tokensCss).toMatch(/--runne-accent:\s*#315CFF/)
    expect(tokensCss).toMatch(/--runne-text-on-accent:\s*#FFFFFF/)
    expect(tokensCss).toMatch(/--runne-border:\s*#3A3D43/)
  })

  it('defines spacing and typography tokens in the production stylesheet', () => {
    expect(tokensCss).toMatch(/--runne-space-md:\s*12px/)
    expect(tokensCss).toMatch(/--runne-space-xl:\s*24px/)
    expect(tokensCss).toMatch(/--runne-font-ui:.*Space Grotesk/)
  })

  it('overrides semantic UI tokens for the light theme from Pen variables', () => {
    expect(tokensCss).toMatch(/\[data-theme='light'\][\s\S]*--runne-canvas:\s*#E7EAEE/)
    expect(tokensCss).toMatch(/\[data-theme='light'\][\s\S]*--runne-sidebar:\s*#ECEFF2/)
    expect(tokensCss).toMatch(/\[data-theme='light'\][\s\S]*--runne-workspace:\s*#EFF1F4/)
    expect(tokensCss).toMatch(/\[data-theme='light'\][\s\S]*--runne-surface:\s*#F4F5F7/)
    expect(tokensCss).toMatch(/\[data-theme='light'\][\s\S]*--runne-surface-raised:\s*#E9ECF0/)
    expect(tokensCss).toMatch(/\[data-theme='light'\][\s\S]*--runne-text-on-accent:\s*#FFFFFF/)
    expect(tokensCss).toMatch(/\[data-theme='light'\][\s\S]*--runne-border:\s*#D2D7DE/)
    expect(tokensCss).toMatch(/\[data-theme='light'\][\s\S]*--runne-error-coral:\s*#B42318/)
  })
})
