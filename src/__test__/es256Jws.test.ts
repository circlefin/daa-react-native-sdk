/**
 * Copyright (c) 2026, Circle Internet Group, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { requireOptionalNativeModule } from 'expo-modules-core'
import {
  nativeVerifyPrepareReceiptSignature,
  requireDaaRegistrationNative,
  type DaaRegistrationNativeModule,
} from '../auth/daaRegistrationNative'
import { fromBase64Url, toBase64Url } from '../crypto/base64url'
import {
  SUPPORTED_JWS_ALGORITHMS,
  verifyCompactEs256,
  type PinnedEs256Key,
} from '../crypto/es256Jws'
import { isDaaError } from '../errors'
import { hexToBytes, loadAuthKeyWireFixture, namedHex } from './authKeyWireFixture'
import {
  encodeJsonSegment,
  generateReceiptSigningKey,
  signCompactJws,
  type ReceiptSigningKey,
} from './prepareReceiptSigning'

/**
 * Compact ES256 JWS verification.
 *
 * Signature math is the platform's. In Jest the platform is `jest.setup.js`'s
 * WebCrypto stand-in for the `DaaRegistration` module, so the known-answer and
 * negative vectors below exercise the stand-in and the TypeScript around it —
 * the same arrangement as `crypto/random.ts`. What this file proves about
 * TypeScript is the structural rules: allowlisted `alg`, expected `typ`, `kid`
 * lookup in a pinned set, no key from the token, 64-byte signatures, and
 * payload parsing only after verification.
 */

const TYP = 'test+jws'
const CLAIMS = { iss: 'https://example.invalid', sub: 'receipt', n: 1 }
const requireNative = requireOptionalNativeModule as jest.Mock
const defaultNativeImpl = requireNative.getMockImplementation()

afterEach(() => {
  requireNative.mockReset()
  if (defaultNativeImpl !== undefined) {
    requireNative.mockImplementation(defaultNativeImpl)
  }
})

function pinned(...keys: ReceiptSigningKey[]): PinnedEs256Key[] {
  return keys.map((key) => ({ kid: key.kid, publicKeyX963: key.x963 }))
}

function header(
  key: ReceiptSigningKey,
  extra: Record<string, unknown> = {},
): Record<string, unknown> {
  return { alg: 'ES256', typ: TYP, kid: key.kid, ...extra }
}

async function verify(jws: string, keys: PinnedEs256Key[]) {
  return verifyCompactEs256(jws, { keys, expectedTyp: TYP })
}

describe('verifyCompactEs256', () => {
  it('verifies a real ES256 JWS and returns its header and claims', async () => {
    const key = await generateReceiptSigningKey('k1')
    const result = await verify(await signCompactJws(key, header(key), CLAIMS), pinned(key))
    expect(result.verified).toBe(true)
    if (!result.verified) {
      throw new Error('unreachable')
    }
    expect(result.protectedHeader).toMatchObject({ alg: 'ES256', kid: 'k1', typ: TYP })
    expect(result.payload).toEqual(CLAIMS)
  })

  it('selects the pinned key by kid, so a rotation overlap verifies under either', async () => {
    const [retiring, current] = await Promise.all([
      generateReceiptSigningKey('retiring'),
      generateReceiptSigningKey('current'),
    ])
    for (const key of [retiring, current]) {
      const jws = await signCompactJws(key, header(key), CLAIMS)
      expect((await verify(jws, pinned(retiring, current))).verified).toBe(true)
    }
  })

  it('rejects a kid that names a different pinned key', async () => {
    const [signer, other] = await Promise.all([
      generateReceiptSigningKey('signer'),
      generateReceiptSigningKey('other'),
    ])
    const jws = await signCompactJws(signer, header(signer, { kid: 'other' }), CLAIMS)
    expect(await verify(jws, pinned(signer, other))).toEqual({
      verified: false,
      reason: 'signature_mismatch',
    })
  })

  it('rejects an unknown or missing kid without trying any key', async () => {
    const key = await generateReceiptSigningKey('k1')
    expect(
      await verify(await signCompactJws(key, header(key, { kid: 'k2' }), CLAIMS), pinned(key)),
    ).toEqual({
      verified: false,
      reason: 'unknown_key_id',
    })
    for (const kid of [undefined, '', 7, null]) {
      const jws = await signCompactJws(
        key,
        { alg: 'ES256', typ: TYP, ...(kid === undefined ? {} : { kid }) },
        CLAIMS,
      )
      expect(await verify(jws, pinned(key))).toEqual({ verified: false, reason: 'missing_key_id' })
    }
  })

  it('rejects a signature from a key that is not pinned under that kid', async () => {
    const [signer, pinnedKey] = await Promise.all([
      generateReceiptSigningKey('k1'),
      generateReceiptSigningKey('k1'),
    ])
    const jws = await signCompactJws(signer, header(signer), CLAIMS)
    expect(await verify(jws, pinned(pinnedKey))).toEqual({
      verified: false,
      reason: 'signature_mismatch',
    })
  })

  it('rejects a tampered payload or header while the signature is left alone', async () => {
    const key = await generateReceiptSigningKey('k1')
    const jws = await signCompactJws(key, header(key), CLAIMS)
    const [encodedHeader, encodedPayload, signature] = jws.split('.') as [string, string, string]
    const swappedPayload = `${encodedHeader}.${encodeJsonSegment({ ...CLAIMS, sub: 'x' })}.${signature}`
    const swappedHeader = `${encodeJsonSegment(header(key, { extra: 1 }))}.${encodedPayload}.${signature}`
    for (const tampered of [swappedPayload, swappedHeader]) {
      expect(await verify(tampered, pinned(key))).toEqual({
        verified: false,
        reason: 'signature_mismatch',
      })
    }
  })

  it('rejects every single-bit flip of a valid signature', async () => {
    const key = await generateReceiptSigningKey('k1')
    const jws = await signCompactJws(key, header(key), CLAIMS)
    const [h, p, s] = jws.split('.') as [string, string, string]
    const signature = fromBase64Url(s)
    for (let bit = 0; bit < 512; bit += 37) {
      const flipped = Uint8Array.from(signature)
      flipped[bit >> 3]! ^= 1 << (bit & 7)
      expect((await verify(`${h}.${p}.${toBase64Url(flipped)}`, pinned(key))).verified).toBe(false)
    }
  })
})

describe('verifyCompactEs256 header rules', () => {
  it('allows exactly one algorithm', () => {
    expect(SUPPORTED_JWS_ALGORITHMS).toEqual(['ES256'])
    expect(Object.isFrozen(SUPPORTED_JWS_ALGORITHMS)).toBe(true)
  })

  it('rejects every other alg, including on a genuinely ES256-signed token', async () => {
    const key = await generateReceiptSigningKey('k1')
    for (const alg of [
      'none',
      'ES256K',
      'HS256',
      'RS256',
      'ES384',
      'es256',
      '',
      256,
      null,
      ['ES256'],
    ]) {
      const jws = await signCompactJws(key, header(key, { alg }), CLAIMS)
      expect(await verify(jws, pinned(key))).toEqual({
        verified: false,
        reason: 'unsupported_algorithm',
      })
    }
    const noAlg = await signCompactJws(key, { typ: TYP, kid: key.kid }, CLAIMS)
    expect(await verify(noAlg, pinned(key))).toEqual({
      verified: false,
      reason: 'unsupported_algorithm',
    })
  })

  it('rejects a typ other than the expected one, or none', async () => {
    const key = await generateReceiptSigningKey('k1')
    for (const typ of ['JWT', 'daa-device-authorization+jws', '', undefined]) {
      const jws = await signCompactJws(
        key,
        typ === undefined ? { alg: 'ES256', kid: key.kid } : header(key, { typ }),
        CLAIMS,
      )
      expect(await verify(jws, pinned(key))).toEqual({ verified: false, reason: 'unexpected_type' })
    }
  })

  it('rejects a header that carries or locates a key, even when it verifies', async () => {
    const key = await generateReceiptSigningKey('k1')
    for (const extra of [
      { jwk: { kty: 'EC', crv: 'P-256', x: key.jwk.x, y: key.jwk.y } },
      { jku: 'https://attacker.invalid/jwks.json' },
      { x5u: 'https://attacker.invalid/chain.pem' },
      { x5c: ['MIIB'] },
    ]) {
      const jws = await signCompactJws(key, header(key, extra), CLAIMS)
      expect(await verify(jws, pinned(key))).toEqual({
        verified: false,
        reason: 'header_sources_a_key',
      })
    }
  })

  it('rejects any crit', async () => {
    const key = await generateReceiptSigningKey('k1')
    const jws = await signCompactJws(key, header(key, { crit: ['exp'], exp: 1 }), CLAIMS)
    expect(await verify(jws, pinned(key))).toEqual({
      verified: false,
      reason: 'unsupported_critical_header',
    })
  })

  it('does not read inherited members as header members', async () => {
    const key = await generateReceiptSigningKey('k1')
    const polluted = Object.prototype as Record<string, unknown>
    polluted['alg'] = 'ES256'
    try {
      const jws = await signCompactJws(key, { typ: TYP, kid: key.kid }, CLAIMS)
      expect(await verify(jws, pinned(key))).toEqual({
        verified: false,
        reason: 'unsupported_algorithm',
      })
    } finally {
      delete polluted['alg']
    }
  })
})

describe('verifyCompactEs256 malformed input', () => {
  let key: ReceiptSigningKey
  let jws: string

  beforeAll(async () => {
    key = await generateReceiptSigningKey('k1')
    jws = await signCompactJws(key, header(key), CLAIMS)
  })

  it('rejects anything that is not three non-empty segments', async () => {
    const [h, p, s] = jws.split('.') as [string, string, string]
    for (const value of [
      '',
      h,
      `${h}.${p}`,
      `${jws}.extra`,
      `.${p}.${s}`,
      `${h}..${s}`,
      `${h}.${p}.`,
    ]) {
      expect(await verify(value, pinned(key))).toEqual({
        verified: false,
        reason: 'malformed_compact_serialization',
      })
    }
  })

  it('rejects a header that is not Base64URL JSON of an object', async () => {
    const [, p, s] = jws.split('.') as [string, string, string]
    for (const encoded of [
      '****',
      toBase64Url(new TextEncoder().encode('not json')),
      encodeJsonSegment(['ES256']),
      encodeJsonSegment(null),
    ]) {
      expect(await verify(`${encoded}.${p}.${s}`, pinned(key))).toEqual({
        verified: false,
        reason: 'malformed_protected_header',
      })
    }
  })

  it('rejects a signature that is not exactly 64 decoded bytes before calling the platform', async () => {
    const [h, p] = jws.split('.') as [string, string]
    const native = requireDaaRegistrationNative()
    const spy = jest.spyOn(native, 'verifyPrepareReceiptSignature')
    try {
      for (const signature of [
        '****',
        toBase64Url(new Uint8Array(63)),
        toBase64Url(new Uint8Array(65)),
        toBase64Url(new Uint8Array(72)),
      ]) {
        expect(await verify(`${h}.${p}.${signature}`, pinned(key))).toEqual({
          verified: false,
          reason: 'malformed_signature',
        })
      }
      expect(spy).not.toHaveBeenCalled()
    } finally {
      spy.mockRestore()
    }
  })

  it('parses the payload only after the signature verifies', async () => {
    const [h, , s] = jws.split('.') as [string, string, string]
    const garbage = toBase64Url(new TextEncoder().encode('{not json'))
    expect(await verify(`${h}.${garbage}.${s}`, pinned(key))).toEqual({
      verified: false,
      reason: 'signature_mismatch',
    })
    for (const payload of [['a'], 'text', 42, null]) {
      const signed = await signCompactJws(key, header(key), payload)
      expect(await verify(signed, pinned(key))).toEqual({
        verified: false,
        reason: 'malformed_payload',
      })
    }
  })

  it('refuses a malformed pinned key set as a configuration error', async () => {
    const bad: PinnedEs256Key[][] = [
      [],
      [{ kid: '', publicKeyX963: key.x963 }],
      [
        { kid: 'k1', publicKeyX963: key.x963 },
        { kid: 'k1', publicKeyX963: key.x963 },
      ],
      [{ kid: 'k1', publicKeyX963: key.x963.subarray(0, 33) }],
    ]
    for (const keys of bad) {
      await expect(verify(jws, keys)).rejects.toMatchObject({
        detail: { kind: 'contract_violation' },
      })
    }
  })
})

describe('platform signature verification', () => {
  const fixture = loadAuthKeyWireFixture()
  const native = (): DaaRegistrationNativeModule => requireDaaRegistrationNative()

  async function platformVerify(
    publicKeyX963: Uint8Array,
    message: Uint8Array,
    signature: Uint8Array,
  ) {
    return nativeVerifyPrepareReceiptSignature(native(), {
      publicKeyX963,
      signingInput: message,
      signature,
    })
  }

  /** RFC 6979 §A.2.5 key U, uncompressed. */
  const RFC6979_KEY = hexToBytes(
    '0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6' +
      '7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299',
  )
  const RFC6979_VECTORS = [
    {
      message: 'sample',
      rs:
        'efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716' +
        'f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8',
    },
    {
      message: 'test',
      rs:
        'f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367' +
        '019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083',
    },
  ]

  it('accepts the RFC 6979 P-256/SHA-256 vectors and rejects them crossed', async () => {
    const utf8 = (text: string) => new TextEncoder().encode(text)
    for (const vector of RFC6979_VECTORS) {
      expect(await platformVerify(RFC6979_KEY, utf8(vector.message), hexToBytes(vector.rs))).toBe(
        true,
      )
    }
    expect(
      await platformVerify(RFC6979_KEY, utf8('sample'), hexToBytes(RFC6979_VECTORS[1]!.rs)),
    ).toBe(false)
  })

  it('accepts the canonical wire fixture signature and rejects its tampered forms', async () => {
    const key = hexToBytes(fixture.signedMessage.publicKeyX963Hex)
    const message = hexToBytes(fixture.signedMessage.messageHex)
    const signature = hexToBytes(fixture.signedMessage.rawHex)
    expect(await platformVerify(key, message, signature)).toBe(true)

    const tampered = Uint8Array.from(message)
    tampered[0]! ^= 1
    expect(await platformVerify(key, tampered, signature)).toBe(false)
    expect(
      await platformVerify(hexToBytes(fixture.p256PublicKey.x963Hex), message, signature),
    ).toBe(false)
  })

  it('rejects every scalar-boundary signature the fixture publishes', async () => {
    const key = hexToBytes(fixture.signedMessage.publicKeyX963Hex)
    const message = hexToBytes(fixture.signedMessage.messageHex)
    expect(fixture.rejected.ecdsaRaw.length).toBeGreaterThan(0)
    for (const vector of fixture.rejected.ecdsaRaw) {
      expect(await platformVerify(key, message, hexToBytes(vector.hex))).toBe(false)
    }
  })

  it('rejects a 63- or 65-byte signature', async () => {
    const key = hexToBytes(fixture.signedMessage.publicKeyX963Hex)
    const message = hexToBytes(fixture.signedMessage.messageHex)
    const signature = hexToBytes(fixture.signedMessage.rawHex)
    expect(await platformVerify(key, message, signature.subarray(0, 63))).toBe(false)
    const long = new Uint8Array(65)
    long.set(signature)
    expect(await platformVerify(key, message, long)).toBe(false)
  })

  it('fails closed on an off-curve or malformed key', async () => {
    const message = hexToBytes(fixture.signedMessage.messageHex)
    const signature = hexToBytes(fixture.signedMessage.rawHex)
    for (const name of ['off-curve', 'invalid-marker', 'compressed']) {
      const point = namedHex(fixture.rejected.x963PublicKeys, name)
      await expect(platformVerify(point, message, signature)).rejects.toMatchObject({
        detail: { kind: 'contract_violation' },
      })
    }
  })

  it('counts only a literal true as verified', async () => {
    for (const value of ['true', 1, {}, null, undefined]) {
      const fake = {
        ...native(),
        verifyPrepareReceiptSignature: jest.fn(async () => value as unknown as boolean),
      }
      expect(
        await nativeVerifyPrepareReceiptSignature(fake, {
          publicKeyX963: RFC6979_KEY,
          signingInput: new Uint8Array(1),
          signature: new Uint8Array(64),
        }),
      ).toBe(false)
    }
  })

  it('fails closed on a host whose native module predates the verify function', async () => {
    const withoutVerify: Partial<DaaRegistrationNativeModule> = { ...native() }
    delete withoutVerify.verifyPrepareReceiptSignature
    requireNative.mockImplementation(() => withoutVerify)
    const key = await generateReceiptSigningKey('k1')
    const jws = await signCompactJws(key, header(key), CLAIMS)
    await expect(verify(jws, pinned(key))).rejects.toThrow(
      /verifyPrepareReceiptSignature is required/,
    )
  })

  it('fails closed on a React Native host with no DaaRegistration module', async () => {
    const key = await generateReceiptSigningKey('k1')
    const jws = await signCompactJws(key, header(key), CLAIMS)
    requireNative.mockImplementation(() => null)
    try {
      await verify(jws, pinned(key))
    } catch (err) {
      expect(isDaaError(err)).toBe(true)
      expect((err as Error).message).toMatch(/DaaRegistration module is not available/)
      return
    }
    throw new Error('expected verification to fail closed without the native module')
  })
})
