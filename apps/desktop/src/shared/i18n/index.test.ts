import { describe, expect, it } from 'vitest'

import { createTranslator, localeCatalogs, validateLocaleCatalogs } from './index'

describe('desktop locale catalogs', () => {
  it('has matching production keys in Russian and English', () => {
    expect(validateLocaleCatalogs(localeCatalogs)).toEqual([])
  })

  it('formats stable messages without concatenating sentences', () => {
    expect(createTranslator('ru')('settings.loading', { page: 'настроек' })).toBe('Загрузка настроек')
    expect(createTranslator('en')('settings.retry')).toBe('Retry')
  })
})
