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
  PARENT_ENTITY_ID_DIGEST_DOMAIN,
  PREPARE_RECEIPT_MAX_CLOCK_SKEW_SECONDS,
  PREPARE_RECEIPT_MAX_LENGTH,
  PREPARE_RECEIPT_MIN_LENGTH,
  PREPARE_RECEIPT_TYP,
  checkPrepareReceipt,
  isPrepareReceiptShape,
  parentEntityIdDigest,
  pinnedPrepareReceiptTrustAnchor,
  requirePrepareReceiptTenantScope,
  verifyPrepareReceipt,
  type PrepareReceiptExpectation,
  type PrepareReceiptTrustAnchor,
} from '../auth/prepareReceipt'
import { DAA_ENVIRONMENTS } from '../config'
import { fromBase64Url } from '../crypto/base64url'
import {
  requireDaaRegistrationNative,
  type DaaRegistrationNativeModule,
} from '../auth/daaRegistrationNative'
import { isDaaError } from '../errors'
import {
  generateReceiptSigningKey,
  receiptClaims,
  signReceipt,
  trustAnchorFor,
  type ReceiptSigningKey,
} from './prepareReceiptSigning'

/**
 * The Prepare receipt: shape, the anchor/receipt decision table, and claim
 * binding against the claim set DAA signs. Signatures go through the platform
 * verifier, which in Jest is `jest.setup.js`'s WebCrypto stand-in.
 */

const NOW = 1_790_000_000
const clock = { nowEpochSeconds: () => NOW }

const EXPECTED: PrepareReceiptExpectation = {
  loginRequestId: '3f1a2b4c-5d6e-4f70-8192-a3b4c5d6e7f8',
  nonce: 'V3dQJq2pX2-t70oIlt0EX7I6oZLo_id94-43ywbCAL8',
  provider: 'GOOGLE',
  environment: 'sandbox',
  registrationCodeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
  registrationFlowKeyThumbprint: 'xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M',
}

let key: ReceiptSigningKey
let anchor: PrepareReceiptTrustAnchor

beforeAll(async () => {
  key = await generateReceiptSigningKey('prepare-receipt-sandbox-1')
  anchor = trustAnchorFor([key])
})

async function receipt(
  overrides: Record<string, unknown> = {},
  header: Record<string, unknown> = {},
) {
  return signReceipt(key, receiptClaims(EXPECTED, NOW, overrides), header)
}

/**
 * The message of the expected rejection. A rejected receipt is
 * `prepare_receipt_invalid`; a fault in the SDK's own anchor, expectation, or
 * clock is `contract_violation`. Any other outcome fails the test.
 */
async function rejection(
  operation: Promise<unknown>,
  kind: 'prepare_receipt_invalid' | 'contract_violation' = 'prepare_receipt_invalid',
): Promise<string> {
  try {
    await operation
  } catch (err) {
    if (isDaaError(err) && err.detail.kind === kind) {
      expect(err.detail).toEqual({ kind })
      return err.message
    }
    throw err
  }
  throw new Error('expected the receipt to be rejected')
}

function jws(payloadLength: number): string {
  return `eyJhbGciOiJFUzI1NiJ9.${'a'.repeat(payloadLength)}.c2ln`
}

const VALID = jws(64)

describe('isPrepareReceiptShape', () => {
  it('accepts a compact JWS inside the contract length bounds', () => {
    expect(VALID.length).toBeGreaterThanOrEqual(PREPARE_RECEIPT_MIN_LENGTH)
    expect(isPrepareReceiptShape(VALID)).toBe(true)
  })

  it('rejects a value shorter than the contract minimum', () => {
    const short = jws(1)
    expect(short.length).toBeLessThan(PREPARE_RECEIPT_MIN_LENGTH)
    expect(isPrepareReceiptShape(short)).toBe(false)
  })

  it('rejects a value longer than the contract maximum', () => {
    expect(isPrepareReceiptShape(jws(PREPARE_RECEIPT_MAX_LENGTH))).toBe(false)
  })

  it('rejects anything that is not three Base64URL segments', () => {
    for (const value of [
      '', // empty
      `${'a'.repeat(80)}`, // no separators
      `${'a'.repeat(40)}.${'b'.repeat(40)}`, // two segments (unsecured JWS shape)
      `${'a'.repeat(30)}.${'b'.repeat(30)}.${'c'.repeat(30)}.${'d'.repeat(30)}`, // four (JWE)
      `${'a'.repeat(30)}..${'c'.repeat(40)}`, // empty middle segment
      `${'a'.repeat(30)}.${'b+/'.repeat(20)}.${'c'.repeat(30)}`, // standard Base64, not URL
      `${'a'.repeat(30)}.${'b'.repeat(30)}.${'c'.repeat(30)}=`, // padded
    ]) {
      expect(isPrepareReceiptShape(value)).toBe(false)
    }
  })
})

describe('pinnedPrepareReceiptTrustAnchor', () => {
  it('is unset for every environment', () => {
    for (const environment of DAA_ENVIRONMENTS) {
      expect(pinnedPrepareReceiptTrustAnchor(environment)).toBeNull()
    }
  })
})

describe('checkPrepareReceipt', () => {
  const noExpectation = (): never => {
    throw new Error('no expectation is computed without an anchor')
  }

  it('anchor unset, no receipt: nothing to verify, and nothing is computed', async () => {
    await expect(checkPrepareReceipt(null, null, noExpectation)).resolves.toBeNull()
  })

  it('anchor unset, receipt present: ignored without being read, and login proceeds', async () => {
    // A valid receipt, a malformed one, and values of the wrong type all come
    // back as no receipt: with no anchor, nothing about the receipt is examined.
    for (const present of [await receipt(), 'not-a-jws', '', 42, { alg: 'none' }]) {
      await expect(checkPrepareReceipt(present, null, noExpectation)).resolves.toBeNull()
    }
  })

  it('anchor set, no receipt: fails closed, because the receipt is required', async () => {
    const message = await rejection(checkPrepareReceipt(null, anchor, () => EXPECTED, clock))
    expect(message).toMatch(/requires one/)
  })

  it('anchor set, receipt present: verifies it', async () => {
    const verified = await checkPrepareReceipt(await receipt(), anchor, () => EXPECTED, clock)
    expect(verified).toMatchObject({
      loginRequestId: EXPECTED.loginRequestId,
      nonce: EXPECTED.nonce,
      expiresAtEpochSeconds: NOW + 600,
    })
  })

  it('anchor set, receipt present but wrong: fails closed', async () => {
    const wrong = await receipt({ registrationCodeChallenge: 'x'.repeat(43) })
    await rejection(checkPrepareReceipt(wrong, anchor, () => EXPECTED, clock))
  })

  it('anchor set, receipt present but not a string: fails closed', async () => {
    for (const notAString of [42, { alg: 'none' }, ['a', 'b', 'c']]) {
      expect(
        await rejection(checkPrepareReceipt(notAString, anchor, () => EXPECTED, clock)),
      ).toMatch(/not a compact JWS/)
    }
  })
})

describe('verifyPrepareReceipt claim binding', () => {
  it('accepts the full claim set DAA signs, under its header', async () => {
    const jws = await receipt()
    const [encodedHeader] = jws.split('.') as [string]
    expect(JSON.parse(new TextDecoder().decode(fromBase64Url(encodedHeader)))).toEqual({
      typ: PREPARE_RECEIPT_TYP,
      kid: key.kid,
      alg: 'ES256',
    })
    const verified = await verifyPrepareReceipt(jws, anchor, EXPECTED, clock)
    expect(verified.tenantScope).toEqual({
      customerAppId: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
      parentEntityIdDigest: 'RWVw0KJgIFpk0F50hV4BAIdY983ge-AkxlZeWxSShMs',
    })
  })

  it.each([
    ['registrationCodeChallenge', 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cN'],
    ['registrationFlowKeyThumbprint', 'xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0N'],
    ['loginRequestId', '9f6ead8b-ff88-43fc-af00-7016eef7f4b3'],
    ['nonce', 'another-attempts-nonce-another-attempts-non'],
    ['provider', 'APPLE'],
    ['environment', 'production'],
    ['iss', 'https://elsewhere.invalid'],
    ['aud', 'another-audience'],
  ])('rejects a receipt that binds a different %s', async (name, value) => {
    const message = await rejection(
      verifyPrepareReceipt(await receipt({ [name]: value }), anchor, EXPECTED, clock),
    )
    expect(message).toMatch(new RegExp(`expected ${name}$`))
  })

  it.each([
    'registrationCodeChallenge',
    'registrationFlowKeyThumbprint',
    'loginRequestId',
    'nonce',
    'provider',
    'environment',
    'iss',
    'aud',
    'jti',
  ])('rejects a receipt with no %s', async (name) => {
    const message = await rejection(
      verifyPrepareReceipt(await receipt({ [name]: undefined }), anchor, EXPECTED, clock),
    )
    expect(message).toMatch(new RegExp(name))
  })

  it('reads nonce, not oidcNonce: other claim names do not verify', async () => {
    const placeholder = await receipt({
      nonce: undefined,
      oidcNonce: EXPECTED.nonce,
      oidcState: 'state',
    })
    const message = await rejection(verifyPrepareReceipt(placeholder, anchor, EXPECTED, clock))
    expect(message).toMatch(/expected nonce$/)
  })

  it('does not require a state claim, because DAA signs none', async () => {
    const claims = receiptClaims(EXPECTED, NOW)
    expect(Object.keys(claims).some((name) => /state/i.test(name))).toBe(false)
    await expect(
      verifyPrepareReceipt(await receipt(), anchor, EXPECTED, clock),
    ).resolves.toBeDefined()
  })

  it('accepts aud as an array that contains the anchor audience', async () => {
    const jws = await receipt({ aud: ['other', anchor.audience] })
    await expect(verifyPrepareReceipt(jws, anchor, EXPECTED, clock)).resolves.toBeDefined()
  })

  it('does not read a claim inherited from Object.prototype', async () => {
    const polluted = Object.prototype as Record<string, unknown>
    polluted['nonce'] = EXPECTED.nonce
    try {
      const message = await rejection(
        verifyPrepareReceipt(await receipt({ nonce: undefined }), anchor, EXPECTED, clock),
      )
      expect(message).toMatch(/expected nonce$/)
    } finally {
      delete polluted['nonce']
    }
  })

  it('rejects a receipt signed by a key the anchor does not pin', async () => {
    const stranger = await generateReceiptSigningKey(key.kid)
    const jws = await signReceipt(stranger, receiptClaims(EXPECTED, NOW))
    expect(await rejection(verifyPrepareReceipt(jws, anchor, EXPECTED, clock))).toMatch(
      /signature_mismatch/,
    )
  })

  it('rejects a receipt with another typ or alg', async () => {
    expect(
      await rejection(
        verifyPrepareReceipt(await receipt({}, { typ: 'JWT' }), anchor, EXPECTED, clock),
      ),
    ).toMatch(/unexpected_type/)
    expect(
      await rejection(
        verifyPrepareReceipt(await receipt({}, { alg: 'none' }), anchor, EXPECTED, clock),
      ),
    ).toMatch(/unsupported_algorithm/)
  })

  it('never puts the receipt into the error a consumer would log', async () => {
    const jws = await receipt({ nonce: 'SECRETRECEIPTMARKER'.repeat(3) })
    try {
      await verifyPrepareReceipt(jws, anchor, EXPECTED, clock)
    } catch (err) {
      expect((err as Error).message).not.toMatch(/SECRETRECEIPTMARKER/)
      expect(JSON.stringify(err)).not.toMatch(/SECRETRECEIPTMARKER/)
      expect((err as Error).message).not.toContain(jws.split('.')[1]!)
      return
    }
    throw new Error('expected the receipt to be rejected')
  })
})

describe('verifyPrepareReceipt time claims', () => {
  const skew = 60

  it('accepts a receipt expiring within the clock allowance', async () => {
    const jws = await receipt({ iat: NOW - 700, exp: NOW - skew })
    await expect(verifyPrepareReceipt(jws, anchor, EXPECTED, clock)).resolves.toBeDefined()
  })

  it('rejects a receipt expired beyond the allowance', async () => {
    const jws = await receipt({ iat: NOW - 700, exp: NOW - skew - 1 })
    expect(await rejection(verifyPrepareReceipt(jws, anchor, EXPECTED, clock))).toMatch(/expired/)
  })

  it('rejects an iat or nbf in the future beyond the allowance', async () => {
    expect(
      await rejection(
        verifyPrepareReceipt(await receipt({ iat: NOW + skew + 1 }), anchor, EXPECTED, clock),
      ),
    ).toMatch(/iat is in the future/)
    expect(
      await rejection(
        verifyPrepareReceipt(await receipt({ nbf: NOW + skew + 1 }), anchor, EXPECTED, clock),
      ),
    ).toMatch(/nbf is in the future/)
    await expect(
      verifyPrepareReceipt(await receipt({ iat: NOW + skew }), anchor, EXPECTED, clock),
    ).resolves.toBeDefined()
  })

  it('rejects a receipt that expires before it was issued', async () => {
    const jws = await receipt({ iat: NOW, exp: NOW - 1 })
    expect(await rejection(verifyPrepareReceipt(jws, anchor, EXPECTED, clock))).toMatch(
      /before it was issued/,
    )
  })

  it('requires exp and iat as integer seconds, and rejects milliseconds', async () => {
    for (const [name, value] of [
      ['exp', undefined],
      ['iat', undefined],
      ['exp', (NOW + 600) * 1000],
      ['exp', 'soon'],
      ['iat', NOW + 0.5],
      ['exp', 0],
    ] as const) {
      const message = await rejection(
        verifyPrepareReceipt(await receipt({ [name]: value }), anchor, EXPECTED, clock),
      )
      expect(message).toMatch(new RegExp(name))
    }
  })
})

describe('verifyPrepareReceipt configuration faults', () => {
  it('refuses a malformed anchor', async () => {
    const jws = await receipt()
    for (const bad of [
      { ...anchor, issuer: '' },
      { ...anchor, audience: '' },
      { ...anchor, verificationKeys: [] },
      { ...anchor, maxClockSkewSeconds: PREPARE_RECEIPT_MAX_CLOCK_SKEW_SECONDS + 1 },
      { ...anchor, maxClockSkewSeconds: -1 },
      { ...anchor, verificationKeys: [{ kid: key.kid, jwk: { ...key.jwk, crv: 'P-384' } }] },
      {
        ...anchor,
        verificationKeys: [{ kid: key.kid, jwk: { ...key.jwk, x: key.jwk.x.slice(1) } }],
      },
    ] as PrepareReceiptTrustAnchor[]) {
      expect(
        await rejection(verifyPrepareReceipt(jws, bad, EXPECTED, clock), 'contract_violation'),
      ).toMatch(/trust anchor|verification key|pinned/)
    }
  })

  it('refuses an incomplete expectation', async () => {
    const jws = await receipt()
    for (const name of Object.keys(EXPECTED) as (keyof PrepareReceiptExpectation)[]) {
      const expected = { ...EXPECTED, [name]: '' }
      expect(
        await rejection(verifyPrepareReceipt(jws, anchor, expected, clock), 'contract_violation'),
      ).toMatch(new RegExp(`requires the expected ${name}`))
    }
  })

  it('refuses an anchor whose keys lack distinct, non-empty kids', async () => {
    const jws = await receipt()
    const pinnedKey = anchor.verificationKeys[0]!
    for (const verificationKeys of [
      [{ ...pinnedKey, kid: '' }],
      [pinnedKey, pinnedKey],
    ] as PrepareReceiptTrustAnchor['verificationKeys'][]) {
      expect(
        await rejection(
          verifyPrepareReceipt(jws, { ...anchor, verificationKeys }, EXPECTED, clock),
          'contract_violation',
        ),
      ).toMatch(/kid/)
    }
  })

  it('refuses a clock that is not a positive Unix timestamp', async () => {
    const jws = await receipt()
    for (const now of [0, -1, 1.5, Number.NaN]) {
      expect(
        await rejection(
          verifyPrepareReceipt(jws, anchor, EXPECTED, { nowEpochSeconds: () => now }),
          'contract_violation',
        ),
      ).toMatch(/positive Unix timestamp/)
    }
  })

  it('refuses a receipt outside the contract bounds before touching the signature', async () => {
    expect(await rejection(verifyPrepareReceipt('a.b.c', anchor, EXPECTED, clock))).toMatch(
      /length bounds/,
    )
  })
})

describe('verifyPrepareReceipt without a working platform verifier', () => {
  const requireNative = requireOptionalNativeModule as jest.Mock
  const defaultNativeImpl = requireNative.getMockImplementation()

  afterEach(() => {
    requireNative.mockReset()
    if (defaultNativeImpl !== undefined) {
      requireNative.mockImplementation(defaultNativeImpl)
    }
  })

  function withNative(native: Partial<DaaRegistrationNativeModule> | null): void {
    requireNative.mockImplementation(() => native)
  }

  it('is prepare_receipt_invalid with no DaaRegistration module', async () => {
    const jws = await receipt()
    withNative(null)
    expect(await rejection(verifyPrepareReceipt(jws, anchor, EXPECTED, clock))).toMatch(
      /DaaRegistration module is not available/,
    )
  })

  it('is prepare_receipt_invalid on a module that predates the verify function', async () => {
    const jws = await receipt()
    const withoutVerify: Partial<DaaRegistrationNativeModule> = {
      ...requireDaaRegistrationNative(),
    }
    delete withoutVerify.verifyPrepareReceiptSignature
    withNative(withoutVerify)
    expect(await rejection(verifyPrepareReceipt(jws, anchor, EXPECTED, clock))).toMatch(
      /verifyPrepareReceiptSignature is required/,
    )
  })

  it('is prepare_receipt_invalid when the platform verifier rejects, keeping the cause', async () => {
    const jws = await receipt()
    const nativeFailure = new Error('native verifier failed')
    withNative({
      ...requireDaaRegistrationNative(),
      verifyPrepareReceiptSignature: jest.fn(async () => {
        throw nativeFailure
      }),
    })
    try {
      await verifyPrepareReceipt(jws, anchor, EXPECTED, clock)
    } catch (err) {
      expect(isDaaError(err) && err.detail).toEqual({ kind: 'prepare_receipt_invalid' })
      expect((err as Error).message).toMatch(/signature verification failed/)
      expect((err as Error).message).not.toContain('native verifier failed')
      expect(isDaaError((err as { cause?: unknown }).cause)).toBe(true)
      return
    }
    throw new Error('expected the receipt to be rejected')
  })
})

describe('tenant scope', () => {
  it('pins parentEntityIdDigest to the golden vector DAA publishes', () => {
    expect(PARENT_ENTITY_ID_DIGEST_DOMAIN).toBe('daa-prepare-receipt-parent-entity-digest-v1\u0000')
    expect(parentEntityIdDigest('3fa85f64-5717-4562-b3fc-2c963f66afa6')).toBe(
      'RWVw0KJgIFpk0F50hV4BAIdY983ge-AkxlZeWxSShMs',
    )
  })

  it('refuses a parent entity id that is not a canonical lower-case UUID', () => {
    for (const value of [
      '3FA85F64-5717-4562-B3FC-2C963F66AFA6',
      '3fa85f6457174562b3fc2c963f66afa6',
      '',
    ]) {
      expect(() => parentEntityIdDigest(value)).toThrow(/canonical lower-case UUID/)
    }
  })

  it('compares both tenant claims when a caller supplies the expected scope', async () => {
    const verified = await verifyPrepareReceipt(await receipt(), anchor, EXPECTED, clock)
    const scope = {
      customerAppId: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
      parentEntityId: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
    }
    expect(() => requirePrepareReceiptTenantScope(verified, scope)).not.toThrow()
    expect(() =>
      requirePrepareReceiptTenantScope(verified, { ...scope, customerAppId: 'another-app' }),
    ).toThrow(/expected customerAppId/)
    try {
      requirePrepareReceiptTenantScope(verified, { ...scope, customerAppId: 'another-app' })
    } catch (err) {
      expect(isDaaError(err) && err.detail).toEqual({ kind: 'prepare_receipt_invalid' })
    }
    expect(() =>
      requirePrepareReceiptTenantScope(verified, {
        ...scope,
        parentEntityId: '00000000-0000-4000-8000-000000000001',
      }),
    ).toThrow(/expected parentEntityIdDigest/)
  })

  it('rejects a receipt missing either tenant claim when the comparison is used', async () => {
    const verified = await verifyPrepareReceipt(
      await receipt({ parentEntityIdDigest: undefined }),
      anchor,
      EXPECTED,
      clock,
    )
    expect(() =>
      requirePrepareReceiptTenantScope(verified, {
        customerAppId: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
        parentEntityId: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
      }),
    ).toThrow(/expected parentEntityIdDigest/)
  })
})
