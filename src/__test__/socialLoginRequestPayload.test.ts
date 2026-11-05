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

import { checkPrepareReceipt } from '../auth/prepareReceipt'
import { MalformedPayloadError } from '../wire/payload'
import { toSocialLoginRequest } from '../wire/socialLoginRequestPayload'

/** The `SocialLoginRequest` decoder: the contract's five required fields. */

const LOGIN_REQUEST_ID = '3f1a2b4c-5d6e-4f70-8192-a3b4c5d6e7f8'
const NONCE = 'n'.repeat(32)
const STATE = 's'.repeat(32)
const RECEIPT = `eyJhbGciOiJFUzI1NiJ9.${'p'.repeat(64)}.c2ln`

/**
 * A `201` body captured verbatim from the service for the SDK's own Prepare
 * request. Four fields, no `prepareReceiptJws`, and
 * `expiresAt` as a JSON number of epoch milliseconds rather than the contract's ISO-8601
 * string. Kept as a literal so it stays what the service actually said.
 */
const CAPTURED_PREPARE_RESPONSE = {
  loginRequestId: '9f6ead8b-ff88-43fc-af00-7016eef7f4b3',
  oidcNonce: 'V3dQJq2pX2-t70oIlt0EX7I6oZLo_id94-43ywbCAL8',
  oidcState: 'VVOX5X68MHIBzK2K8eVOtad3pQAFGs2vDxY43QosYAA',
  expiresAt: 1788290024580,
}

/** `CAPTURED_PREPARE_RESPONSE.expiresAt` in the form the decoder must normalise to. */
const CAPTURED_EXPIRES_AT_ISO = '2026-09-01T19:13:44.580Z'

function payload(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    loginRequestId: LOGIN_REQUEST_ID,
    oidcNonce: NONCE,
    oidcState: STATE,
    expiresAt: '2026-08-26T12:00:00Z',
    prepareReceiptJws: RECEIPT,
    ...overrides,
  }
}

describe('toSocialLoginRequest', () => {
  it('reads every field the contract guarantees', () => {
    expect(toSocialLoginRequest(payload())).toEqual({
      loginRequestId: LOGIN_REQUEST_ID,
      oidcNonce: NONCE,
      oidcState: STATE,
      expiresAt: '2026-08-26T12:00:00Z',
      prepareReceiptJws: RECEIPT,
    })
  })

  it('treats a missing receipt as null rather than malformed', () => {
    const { prepareReceiptJws, ...withoutReceipt } = payload()
    expect(prepareReceiptJws).toBe(RECEIPT)
    expect(toSocialLoginRequest(withoutReceipt).prepareReceiptJws).toBeNull()
    expect(toSocialLoginRequest(payload({ prepareReceiptJws: null })).prepareReceiptJws).toBeNull()
  })

  it('ignores unknown fields rather than failing the response', () => {
    const decoded = toSocialLoginRequest(payload({ authKeyId: LOGIN_REQUEST_ID, extra: 1 }))
    expect(Object.keys(decoded).sort()).toEqual([
      'expiresAt',
      'loginRequestId',
      'oidcNonce',
      'oidcState',
      'prepareReceiptJws',
    ])
  })

  it('carries a receipt through raw, whatever it is, for the receipt check to judge', () => {
    // Rejecting a malformed receipt here would fail login on an SDK with no
    // trust anchor, which is meant to ignore the receipt.
    for (const receipt of ['', 'not-a-jws', `${'a'.repeat(30)}.${'b'.repeat(30)}`, 42, {}]) {
      expect(toSocialLoginRequest(payload({ prepareReceiptJws: receipt })).prepareReceiptJws).toBe(
        receipt,
      )
    }
  })

  it('rejects a non-UUID login request id', () => {
    expect(() => toSocialLoginRequest(payload({ loginRequestId: 'login-1' }))).toThrow(
      MalformedPayloadError,
    )
  })

  it('enforces the contract length bounds on the OIDC values', () => {
    // Both bounds are stated as reject-just-outside plus accept-exactly-at.
    // The base fixture is 32 characters, so the accept-at-minimum case is
    // asserted on its own: an off-by-one that widens the minimum fails here.
    for (const field of ['oidcNonce', 'oidcState']) {
      expect(() => toSocialLoginRequest(payload({ [field]: 'x'.repeat(31) }))).toThrow(
        MalformedPayloadError,
      )
      expect(toSocialLoginRequest(payload({ [field]: 'x'.repeat(32) }))).toBeDefined()
      expect(toSocialLoginRequest(payload({ [field]: 'x'.repeat(256) }))).toBeDefined()
      expect(() => toSocialLoginRequest(payload({ [field]: 'x'.repeat(257) }))).toThrow(
        MalformedPayloadError,
      )
    }
  })

  it('rejects a timestamp that is not the service ISO-8601 form', () => {
    for (const expiresAt of ['2026-08-26', '2026-08-26 12:00:00Z', 'later']) {
      expect(() => toSocialLoginRequest(payload({ expiresAt }))).toThrow(MalformedPayloadError)
    }
    expect(
      toSocialLoginRequest(payload({ expiresAt: '2026-08-26T12:00:00.123+02:00' })),
    ).toBeDefined()
  })

  it('decodes the response the service sends', () => {
    // Number `expiresAt`, no receipt. Both diverge from the contract OpenAPI and
    // both are what the service returns, so the decoder has to take them.
    expect(toSocialLoginRequest(CAPTURED_PREPARE_RESPONSE)).toEqual({
      loginRequestId: '9f6ead8b-ff88-43fc-af00-7016eef7f4b3',
      oidcNonce: 'V3dQJq2pX2-t70oIlt0EX7I6oZLo_id94-43ywbCAL8',
      oidcState: 'VVOX5X68MHIBzK2K8eVOtad3pQAFGs2vDxY43QosYAA',
      expiresAt: CAPTURED_EXPIRES_AT_ISO,
      prepareReceiptJws: null,
    })
  })

  it('normalises epoch milliseconds to the same text the string form carries', () => {
    // Pinned, not assumed: an off-by-a-unit reading (seconds, or microseconds)
    // would still produce a `DATE_TIME`-shaped string and pass a shape-only check.
    expect(toSocialLoginRequest(payload({ expiresAt: 1788290024580 })).expiresAt).toBe(
      CAPTURED_EXPIRES_AT_ISO,
    )
    expect(toSocialLoginRequest(payload({ expiresAt: 1 })).expiresAt).toBe(
      '1970-01-01T00:00:00.001Z',
    )
    // The string form is passed through untouched, so both wire forms land on one
    // public type without the ISO input being rewritten.
    expect(toSocialLoginRequest(payload({ expiresAt: '2026-08-26T12:00:00Z' })).expiresAt).toBe(
      '2026-08-26T12:00:00Z',
    )
  })

  it('rejects an epoch timestamp that is not a plausible count of milliseconds', () => {
    for (const expiresAt of [
      1788290024580.5, // fractional
      -1788290024580, // negative
      0, // the epoch itself is a dropped field, not an expiry
      8.64e15 + 1, // past the largest instant `Date` represents
      1e15, // renders a year `DATE_TIME` cannot spell
      Number.NaN,
      Number.POSITIVE_INFINITY,
      Number.MAX_SAFE_INTEGER,
    ]) {
      expect(() => toSocialLoginRequest(payload({ expiresAt }))).toThrow(MalformedPayloadError)
    }
  })

  it('leaves the receipt decision to the check, which ignores any receipt without an anchor', async () => {
    // Decoding a receipt, or its absence, buys no trust: with no trust anchor
    // pinned the check ignores both alike, and with one it requires a receipt.
    const decoded = toSocialLoginRequest(CAPTURED_PREPARE_RESPONSE)
    expect(decoded.prepareReceiptJws).toBeNull()
    const expected = (): never => {
      throw new Error('no expectation is computed without an anchor')
    }
    await expect(checkPrepareReceipt(decoded.prepareReceiptJws, null, expected)).resolves.toBeNull()
    await expect(checkPrepareReceipt(RECEIPT, null, expected)).resolves.toBeNull()
  })

  it('rejects a payload that is not an object', () => {
    for (const value of [null, [], 'x', 7]) {
      expect(() => toSocialLoginRequest(value)).toThrow(MalformedPayloadError)
    }
  })
})
