import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import FileExplorer from './FileExplorer.vue'

describe('FileExplorer', () => {
  it('offers an explicit editor action only for regular files', async () => {
    let opened = ''
    const wrapper = mount(FileExplorer, {
      props: {
        entries: [
          { path: 'src', kind: 'directory', sizeBytes: 0 },
          { path: 'src/main.rs', kind: 'file', sizeBytes: 12 },
        ],
        loading: false,
        error: false,
        openFile: async (path: string) => { opened = path },
      },
    })

    const buttons = wrapper.findAll('button')
    expect(buttons).toHaveLength(1)
    expect(wrapper.get('ul').classes()).toContain('file-explorer__list')
    expect(wrapper.findAll('.file-explorer__entry')).toHaveLength(2)
    expect(wrapper.findAll('.file-explorer__icon svg')).toHaveLength(2)
    expect(wrapper.get('.file-explorer__path').text()).toBe('src')
    expect(wrapper.get('.file-explorer__action').text()).toBe('Open')
    await buttons[0]!.trigger('click')
    expect(opened).toBe('src/main.rs')
  })

  it('disables editor actions in read-only state', () => {
    const wrapper = mount(FileExplorer, {
      props: {
        entries: [{ path: 'main.rs', kind: 'file', sizeBytes: 12 }],
        loading: false,
        error: false,
        disabled: true,
      },
    })

    expect(wrapper.get('button').attributes('disabled')).toBeDefined()
  })
})
