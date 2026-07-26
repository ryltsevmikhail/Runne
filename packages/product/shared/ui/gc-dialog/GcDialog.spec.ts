import { describe, it, expect, afterEach } from 'vitest'
import { mount } from '@vue/test-utils'
import GcDialog from './GcDialog.vue'

function query(selector: string): Element | null {
  return document.body.querySelector(selector)
}

afterEach(() => {
  document.body.innerHTML = ''
})

describe('GcDialog', () => {
  it('does not render when open is false', () => {
    mount(GcDialog, { props: { open: false, title: 'Test' } })
    expect(query('.gc-dialog-overlay')).toBeNull()
  })

  it('renders title and description', () => {
    mount(GcDialog, {
      props: { open: true, title: 'Title', description: 'Description' },
    })
    const overlay = query('.gc-dialog-overlay')
    expect(overlay?.textContent).toContain('Title')
    expect(overlay?.textContent).toContain('Description')
    const dialog = query('[role="dialog"]') as HTMLElement
    expect(dialog.getAttribute('aria-labelledby')).toBeTruthy()
    expect(dialog.getAttribute('aria-describedby')).toBeTruthy()
  })

  it('uses non-submitting dialog actions', () => {
    mount(GcDialog, { props: { open: true, title: 'Title' } })
    expect(query('.gc-dialog-btn--cancel')?.getAttribute('type')).toBe('button')
    expect(query('.gc-dialog-btn:not(.gc-dialog-btn--cancel)')?.getAttribute('type')).toBe('button')
  })

  it('renders default slot', () => {
    mount(GcDialog, {
      props: { open: true, title: 'Title' },
      slots: { default: 'Slot content' },
    })
    const overlay = query('.gc-dialog-overlay')
    expect(overlay?.textContent).toContain('Slot content')
  })

  it('emits confirm when confirm button is clicked', async () => {
    const wrapper = mount(GcDialog, {
      props: { open: true, title: 'Title' },
    })
    const btn = query('.gc-dialog-btn:not(.gc-dialog-btn--cancel)') as HTMLElement | null
    btn?.click()
    await wrapper.vm.$nextTick()
    expect(wrapper.emitted('confirm')).toBeTruthy()
  })

  it('emits cancel when cancel button is clicked', async () => {
    const wrapper = mount(GcDialog, {
      props: { open: true, title: 'Title' },
    })
    const btn = query('.gc-dialog-btn--cancel') as HTMLElement | null
    btn?.click()
    await wrapper.vm.$nextTick()
    expect(wrapper.emitted('cancel')).toBeTruthy()
  })

  it('shows danger styling on confirm button when danger is true', () => {
    mount(GcDialog, {
      props: { open: true, title: 'Title', danger: true },
    })
    expect(query('.gc-dialog-btn--danger')).not.toBeNull()
  })

  it('emits cancel when overlay is clicked', async () => {
    const wrapper = mount(GcDialog, {
      props: { open: true, title: 'Title' },
    })
    const overlay = query('.gc-dialog-overlay') as HTMLElement | null
    overlay?.click()
    await wrapper.vm.$nextTick()
    expect(wrapper.emitted('cancel')).toBeTruthy()
  })
})
