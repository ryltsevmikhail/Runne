import { describe, it, expect } from 'vitest'

describe('CSS tokens', () => {
  it('defines brand identity colors', () => {
    const styles = getComputedStyle(document.documentElement)
    expect(styles.getPropertyValue('--gocode-graphite').trim()).toBe('#151616')
    expect(styles.getPropertyValue('--gocode-accent').trim()).toBe('#F47832')
    expect(styles.getPropertyValue('--gocode-lead-green').trim()).toBe('#4DCA81')
  })

  it('defines spacing tokens', () => {
    const styles = getComputedStyle(document.documentElement)
    expect(styles.getPropertyValue('--gocode-space-md').trim()).toBe('12px')
    expect(styles.getPropertyValue('--gocode-space-xl').trim()).toBe('24px')
  })

  it('defines typography tokens', () => {
    const styles = getComputedStyle(document.documentElement)
    const font = styles.getPropertyValue('--gocode-font-ui').trim()
    expect(font).toContain('Inter')
  })
})
