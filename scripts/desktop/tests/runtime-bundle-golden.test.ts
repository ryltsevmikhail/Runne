import { describe, it, expect } from 'vitest'

// Mirror of Rust BundleManifest::canonical_bytes()
function canonicalBundleBytes(runtimeCommit: string): Uint8Array {
  const RS = 0x1E
  const NL = 0x0A
  const BUNDLE_ID = 'gocode-ui-client/1'
  
  const events = [
    'TaskRunCreated','TaskRunAdmitted','TaskRunQueued','TaskRunStarted',
    'TaskRunCompleted','TaskRunFailed','TaskRunCancelled','TaskRunRetried',
    'TaskRunCheckpointStarted','TaskRunCheckpointCommitted',
    'TaskRunReconciliationStarted','TaskRunReconciliationCompleted',
    'TaskRunUnrecoverable','TaskRunWaitingForApproval','TaskRunResumed',
    'TaskRunBudgetExhausted','TaskRunPolicyDenied',
    'ConversationCreated','ConversationMessageAdded',
    'WorkspaceCreated','WorkspaceUpdated',
  ].join(',')

  const commands = [
    'CreateTaskRun','Admit','StartAttempt','Queue','WaitForApproval',
    'Resume','StartRetry','CompleteRetry','StartCheckpoint',
    'CommitCheckpoint','RequestCancellation','CompleteCancellation',
    'Complete','Fail','StartReconciliation','CompleteReconciliation',
    'MarkUnrecoverable',
  ].join(',')

  const aggregates = ['TaskRun','Conversation','Workspace'].join(',')

  const text = `${BUNDLE_ID}${String.fromCharCode(RS)}${runtimeCommit}${String.fromCharCode(NL)}` +
    `EVENTS${String.fromCharCode(RS)}${events}${String.fromCharCode(NL)}` +
    `COMMANDS${String.fromCharCode(RS)}${commands}${String.fromCharCode(NL)}` +
    `AGGREGATES${String.fromCharCode(RS)}${aggregates}${String.fromCharCode(NL)}`

  return new TextEncoder().encode(text)
}

const PLACEHOLDER = '0000000000000000000000000000000000000000'
const PINNED_COMMIT = '6311992cea0551dab406a93b855ce2c49507e07e'
const GOLDEN_HASH = 'bc9b2d46b617ae1ef7c0bfad6b5ce8655779d5299822421d999b3f2a0b181429'

describe('Runtime bundle golden vectors (TypeScript)', () => {
  it('produce canonical bytes identical to Rust', () => {
    const bytes = canonicalBundleBytes(PLACEHOLDER)
    expect(bytes.length).toBe(773)
    expect(bytes[0]).toBe('g'.charCodeAt(0))
  })

  it('golden hash with pinned commit matches Rust', async () => {
    const bytes = canonicalBundleBytes(PINNED_COMMIT)
    const hashBuffer = await crypto.subtle.digest('SHA-256', bytes)
    const hashHex = Array.from(new Uint8Array(hashBuffer))
      .map(b => b.toString(16).padStart(2, '0')).join('')
    expect(hashHex).toBe(GOLDEN_HASH)
  })

  it('golden hash with placeholder commit is stable', async () => {
    const bytes = canonicalBundleBytes(PLACEHOLDER)
    const hashBuffer = await crypto.subtle.digest('SHA-256', bytes)
    const hashHex = Array.from(new Uint8Array(hashBuffer))
      .map(b => b.toString(16).padStart(2, '0')).join('')
    expect(hashHex).toBe('6eae1a1b3fb7cb216d1ca7a9d1ce6b6087f28976e5e50a84031da8fea57d2c4b')
  })

  it('pinned commit produces different hash than placeholder', async () => {
    const placeholder = canonicalBundleBytes(PLACEHOLDER)
    const pinned = canonicalBundleBytes(PINNED_COMMIT)
    
    expect(placeholder.length).toBe(pinned.length)
    // Commits differ — bytes should differ
    expect([...placeholder]).not.toEqual([...pinned])
  })

  it('format is correct — no spaces, correct separators', () => {
    const bytes = canonicalBundleBytes(PLACEHOLDER)
    const text = new TextDecoder().decode(bytes)
    expect(text.startsWith('gocode-ui-client/1\x1E')).toBe(true)
    expect(text.includes('EVENTS\x1E')).toBe(true)
    expect(text.includes('COMMANDS\x1E')).toBe(true)
    expect(text.includes('AGGREGATES\x1E')).toBe(true)
    expect(text.endsWith('\n')).toBe(true)
    expect(text).not.toContain(' ')
  })
})
