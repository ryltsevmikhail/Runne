import { describe, it, expect, afterEach } from 'vitest'
import { mount } from '@vue/test-utils'
import GcCommandPalette from './GcCommandPalette.vue'
import type { CommandItem } from './GcCommandPalette.types'

const items: CommandItem[] = [
  { id: '1', label: 'New Project' },
  { id: '2', label: 'Open Settings' },
  { id: '3', label: 'Export Data' },
]

function query(selector: string): Element | null {
  return document.body.querySelector(selector)
}

afterEach(() => {
  document.body.innerHTML = ''
})

describe('GcCommandPalette', () => {
  it('does not render when open is false', () => {
    mount(GcCommandPalette, { props: { open: false, items } })
    expect(query('.gc-palette-overlay')).toBeNull()
  })

  it('renders items', () => {
    mount(GcCommandPalette, { props: { open: true, items } })
    const overlay = query('.gc-palette-overlay')
    expect(overlay?.textContent).toContain('New Project')
    expect(overlay?.textContent).toContain('Open Settings')
    expect(overlay?.textContent).toContain('Export Data')
  })

  it('filters by search', async () => {
    const wrapper = mount(GcCommandPalette, { props: { open: true, items } })
    const input = query('.gc-palette-search') as HTMLInputElement | null
    expect(input).not.toBeNull()
    input!.value = 'Settings'
    input!.dispatchEvent(new Event('input'))
    await wrapper.vm.$nextTick()
    const overlay = query('.gc-palette-overlay')
    expect(overlay?.textContent).toContain('Open Settings')
    expect(overlay?.textContent).not.toContain('New Project')
    expect(overlay?.textContent).not.toContain('Export Data')
  })

  it('emits select when item is clicked', async () => {
    const wrapper = mount(GcCommandPalette, { props: { open: true, items } })
    const item = query('.gc-palette-item') as HTMLElement | null
    item?.click()
    await wrapper.vm.$nextTick()
    expect(wrapper.emitted('select')).toBeTruthy()
    expect(wrapper.emitted('select')?.[0]).toEqual(['1'])
  })

  it('emits close on Escape', async () => {
    const wrapper = mount(GcCommandPalette, { props: { open: true, items } })
    const palette = query('.gc-palette') as HTMLElement | null
    palette?.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }))
    await wrapper.vm.$nextTick()
    expect(wrapper.emitted('close')).toBeTruthy()
  })

  it('shows "No results" for empty filtered result', async () => {
    const wrapper = mount(GcCommandPalette, { props: { open: true, items } })
    const input = query('.gc-palette-search') as HTMLInputElement | null
    expect(input).not.toBeNull()
    input!.value = 'nonexistent'
    input!.dispatchEvent(new Event('input'))
    await wrapper.vm.$nextTick()
    const overlay = query('.gc-palette-overlay')
    expect(overlay?.textContent).toContain('No results')
  })

  it('clamps the active selection when filtering removes earlier items', async () => {
    const wrapper = mount(GcCommandPalette, { props: { open: true, items } })
    const palette = query('.gc-palette') as HTMLElement
    palette.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true }))
    palette.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true }))
    const input = query('.gc-palette-search') as HTMLInputElement
    input.value = 'Settings'
    input.dispatchEvent(new Event('input'))
    await wrapper.vm.$nextTick()
    palette.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }))
    await wrapper.vm.$nextTick()
    expect(wrapper.emitted('select')?.[0]).toEqual(['2'])
  })
})
