import { ref } from 'vue'

export type AppTheme = 'dark' | 'light'

export interface ThemeAcknowledgement {
  readonly theme: AppTheme
}

type SaveTheme = (theme: AppTheme) => Promise<unknown>

/** Renderer projection of the Rust-owned persisted theme setting. */
export const appTheme = ref<AppTheme>('dark')
export const themeWritePending = ref(false)

let pendingThemeWrite: Promise<ThemeAcknowledgement> | null = null
let themeWriteOrder = 0

export function captureThemeRead(): number | null {
  return pendingThemeWrite === null ? themeWriteOrder : null
}

export function applyOwnerTheme(theme: AppTheme, readOrder: number | null): boolean {
  if (readOrder === null || pendingThemeWrite !== null || readOrder !== themeWriteOrder) return false
  appTheme.value = theme
  return true
}

export async function commitTheme(
  theme: AppTheme,
  save: SaveTheme,
): Promise<ThemeAcknowledgement | null> {
  if (pendingThemeWrite !== null) return null
  themeWriteOrder += 1
  themeWritePending.value = true
  const completion = Promise.resolve()
    .then(() => save(theme))
    .then((acknowledgement) => {
      if (!isThemeAcknowledgement(acknowledgement) || acknowledgement.theme !== theme) {
        throw new Error('Invalid theme acknowledgement')
      }
      appTheme.value = acknowledgement.theme
      return acknowledgement
    })
  pendingThemeWrite = completion
  try {
    return await completion
  }
  finally {
    if (pendingThemeWrite === completion) {
      pendingThemeWrite = null
      themeWritePending.value = false
    }
  }
}

export function isThemeAcknowledgement(value: unknown): value is ThemeAcknowledgement {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false
  const keys = Object.keys(value)
  if (keys.length !== 1 || keys[0] !== 'theme' || !Object.hasOwn(value, 'theme')) return false
  const theme = (value as Record<string, unknown>).theme
  return theme === 'dark' || theme === 'light'
}
