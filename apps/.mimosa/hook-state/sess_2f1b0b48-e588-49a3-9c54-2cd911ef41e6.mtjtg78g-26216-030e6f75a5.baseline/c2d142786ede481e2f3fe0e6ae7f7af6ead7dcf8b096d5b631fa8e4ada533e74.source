export type SettingsPageItem = {
  readonly label: string
  readonly detail: string
}

export type SettingsPageSnapshot =
  | { readonly kind: 'ready'; readonly items: readonly SettingsPageItem[] }
  | { readonly kind: 'unavailable'; readonly message: string }
  | { readonly kind: 'recovery'; readonly message: string }

export type SettingsPageAdapter = {
  readonly load: () => Promise<SettingsPageSnapshot>
  readonly recover?: () => Promise<SettingsPageSnapshot>
}

export function unavailableSettingsPageAdapter(owner: string): SettingsPageAdapter {
  const unavailable = async (): Promise<SettingsPageSnapshot> => ({
    kind: 'unavailable',
    message: `${owner} is unavailable until its desktop owner is connected.`,
  })

  return { load: unavailable, recover: unavailable }
}
