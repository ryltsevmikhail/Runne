export interface ApplicationInfo {
  readonly name: string
  readonly version: string
  readonly platform: 'macos' | 'windows' | 'linux'
}

export interface PlatformPort {
  getApplicationInfo(): Promise<ApplicationInfo>
}
