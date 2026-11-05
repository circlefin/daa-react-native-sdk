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

// Receipt-signing material for tests: a WebCrypto P-256 key standing in for
// DAA's receipt-signing key, and a compact-JWS signer that emits the receipt
// DAA signs.
//
// Not a test file — Jest's `testMatch` is `**/__test__/**/*.test.ts`, so this
// module is only ever imported, never collected.

import {
  PREPARE_RECEIPT_TYP,
  type PrepareReceiptExpectation,
  type PrepareReceiptTrustAnchor,
} from '../auth/prepareReceipt'
import { toBase64Url } from '../crypto/base64url'
import { toArrayBuffer } from '../crypto/bytes'
import type { P256PublicJwk } from '../crypto/jwkThumbprint'

export type ReceiptSigningKey = Readonly<{
  kid: string
  privateKey: CryptoKey
  jwk: P256PublicJwk
  x963: Uint8Array
}>

export async function generateReceiptSigningKey(kid = 'receipt-key-1'): Promise<ReceiptSigningKey> {
  const pair = (await globalThis.crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair
  const x963 = new Uint8Array(await globalThis.crypto.subtle.exportKey('raw', pair.publicKey))
  return {
    kid,
    privateKey: pair.privateKey,
    jwk: {
      kty: 'EC',
      crv: 'P-256',
      x: toBase64Url(x963.subarray(1, 33)),
      y: toBase64Url(x963.subarray(33, 65)),
    },
    x963,
  }
}

export function encodeJsonSegment(value: unknown): string {
  return toBase64Url(new TextEncoder().encode(JSON.stringify(value)))
}

/** Sign an arbitrary header/payload pair into a compact JWS. */
export async function signCompactJws(
  key: ReceiptSigningKey,
  header: Record<string, unknown>,
  payload: unknown,
): Promise<string> {
  const signingInput = `${encodeJsonSegment(header)}.${encodeJsonSegment(payload)}`
  const signature = new Uint8Array(
    await globalThis.crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      key.privateKey,
      toArrayBuffer(new TextEncoder().encode(signingInput)),
    ),
  )
  return `${signingInput}.${toBase64Url(signature)}`
}

export const RECEIPT_ISSUER = 'https://daa.example.invalid'
export const RECEIPT_AUDIENCE = 'daa-sdk.example.invalid'

export function trustAnchorFor(
  keys: readonly ReceiptSigningKey[],
  overrides: Partial<PrepareReceiptTrustAnchor> = {},
): PrepareReceiptTrustAnchor {
  return {
    issuer: RECEIPT_ISSUER,
    audience: RECEIPT_AUDIENCE,
    verificationKeys: keys.map((key) => ({ kid: key.kid, jwk: key.jwk })),
    maxClockSkewSeconds: 60,
    ...overrides,
  }
}

/** Every claim DAA's signer sets, bound to `expected`. */
export function receiptClaims(
  expected: PrepareReceiptExpectation,
  nowEpochSeconds: number,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    iss: RECEIPT_ISSUER,
    aud: RECEIPT_AUDIENCE,
    jti: '6f1c2d3e-4b5a-4c6d-8e7f-0a1b2c3d4e5f',
    environment: expected.environment,
    customerAppId: '3fa85f64-5717-4562-b3fc-2c963f66afa6',
    parentEntityIdDigest: 'RWVw0KJgIFpk0F50hV4BAIdY983ge-AkxlZeWxSShMs',
    provider: expected.provider,
    loginRequestId: expected.loginRequestId,
    nonce: expected.nonce,
    registrationCodeChallenge: expected.registrationCodeChallenge,
    registrationFlowKeyThumbprint: expected.registrationFlowKeyThumbprint,
    iat: nowEpochSeconds,
    exp: nowEpochSeconds + 600,
    ...overrides,
  }
}

/** A receipt with DAA's header: `typ`, `kid`, `alg`. */
export async function signReceipt(
  key: ReceiptSigningKey,
  claims: Record<string, unknown>,
  header: Record<string, unknown> = {},
): Promise<string> {
  return signCompactJws(
    key,
    { typ: PREPARE_RECEIPT_TYP, kid: key.kid, alg: 'ES256', ...header },
    claims,
  )
}
