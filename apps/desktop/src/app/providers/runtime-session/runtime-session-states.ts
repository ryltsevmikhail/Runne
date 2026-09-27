// These are valid in-flight stages; they revoke current proof and trigger a
// fresh authenticated connection without granting mutation access themselves.
export const TRANSIENT_STATES = new Set<string>([
  'reconnecting',
  'profile_loaded',
  'peer_verified',
  'bootstrap_proved',
  'authenticated',
  'reconciling',
])

export const REVOKED_STATES = new Set<string>([
  'incompatible',
  'revoked',
  'fatal',
])
