import { ref } from 'vue'

export type AppTheme = 'dark' | 'light'

/** Renderer projection of the Rust-owned persisted theme setting. */
export const appTheme = ref<AppTheme>('dark')
