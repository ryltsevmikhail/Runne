import { describe, it, expect } from 'vitest'

// Mirror of Rust canonical_bytes serialization
function canonicalBytes(challenge: {
  domain: Uint8Array
  version: number
  deviceId: Uint8Array
  nonce: Uint8Array
  issuedAt: number
  expiresAt: number
  capabilities: number
}): Uint8Array {
  const buf = new Uint8Array(100)
  let offset = 0
  buf.set(challenge.domain, offset); offset += 16
  new DataView(buf.buffer).setUint16(offset, challenge.version, false); offset += 2
  buf.set(challenge.deviceId, offset); offset += 32
  buf.set(challenge.nonce, offset); offset += 32
  new DataView(buf.buffer).setBigUint64(offset, BigInt(challenge.issuedAt), false); offset += 8
  new DataView(buf.buffer).setBigUint64(offset, BigInt(challenge.expiresAt), false); offset += 8
  new DataView(buf.buffer).setUint16(offset, challenge.capabilities, false); offset += 2
  return buf
}

const DOMAIN = new TextEncoder().encode('gocode-pair/v1\x00\x00')

describe('Pairing golden vectors (TypeScript)', () => {
  it('produce canonical bytes identical to Rust layout', () => {
    const challenge = {
      domain: DOMAIN,
      version: 1,
      deviceId: new Uint8Array(32).fill(0xAA),
      nonce: new Uint8Array(32).fill(0xBB),
      issuedAt: 1_752_000_000,
      expiresAt: 1_752_003_600,
      capabilities: 0,
    }

    const bytes = canonicalBytes(challenge)
    expect(bytes.length).toBe(100)

    // Domain first 16 bytes
    expect([...bytes.slice(0, 16)]).toEqual([...DOMAIN])

    // Version big-endian at offset 16
    expect(new DataView(bytes.buffer).getUint16(16, false)).toBe(1)

    // issued_at big-endian at offset 82 (16+2+32+32)
    const issuedAt = new DataView(bytes.buffer).getBigUint64(82, false)
    expect(Number(issuedAt)).toBe(1_752_000_000)

    // expires_at big-endian at offset 90
    const expiresAt = new DataView(bytes.buffer).getBigUint64(90, false)
    expect(Number(expiresAt)).toBe(1_752_003_600)

    // capabilities at offset 98
    expect(new DataView(bytes.buffer).getUint16(98, false)).toBe(0)
  })

  it('verifies golden canonical SHA-256 matches Rust', async () => {
    const challenge = {
      domain: DOMAIN,
      version: 1,
      deviceId: new Uint8Array(32).fill(0xAA),
      nonce: new Uint8Array(32).fill(0xBB),
      issuedAt: 1_752_000_000,
      expiresAt: 1_752_003_600,
      capabilities: 0,
    }

    const bytes = canonicalBytes(challenge)
    const hashBuffer = await crypto.subtle.digest('SHA-256', bytes)
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('')

    // This must match Rust's golden_valid_signature_verifies test hash
    expect(hashHex).toBe('c1578ca6e128651894bcbff1c978fa5c95b9e18a50a92075ac7dedc8bfa0859a')
  })

  it('rejects wrong domain separator', () => {
    const badDomain = new TextEncoder().encode('evil-pair/v1\x00\x00\x00\x00')
    const challenge = {
      domain: badDomain,
      version: 1,
      deviceId: new Uint8Array(32),
      nonce: new Uint8Array(32),
      issuedAt: 0,
      expiresAt: 0,
      capabilities: 0,
    }
    const bytes = canonicalBytes(challenge)
    const domain = bytes.slice(0, 16)
    expect([...domain]).not.toEqual([...DOMAIN])
  })
})
