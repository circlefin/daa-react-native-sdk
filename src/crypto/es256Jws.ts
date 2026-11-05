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

// Compact ES256 JWS verification against a pinned key set.
//
// This file does the structural work only. The signature itself is checked by
// the native SDKs' `DaaPrepareReceiptSignature` — CryptoKit on iOS,
// `java.security` on Android — through the Expo `DaaRegistration` module;
// there is no curve arithmetic in TypeScript.
// Node/Jest has no native module, so `jest.setup.js` stands in with WebCrypto,
// the same arrangement `crypto/random.ts` uses. A React Native host without the
// module fails closed.
//
// What this file enforces, and why each rule is here:
//
// - `alg` must be exactly `ES256`. It is compared against a fixed allowlist and
//   never obeyed, which closes `alg: none` and algorithm confusion by
//   construction.
// - `typ` must be the value the caller expects, so a JWS minted for another
//   purpose under the same key does not verify as this one.
// - No key is ever taken from the token. `jwk`/`jku`/`x5u`/`x5c` are rejected
//   outright, even on a token that would verify. `kid` selects among the keys
//   the caller pinned and nothing else: an unknown `kid` is a rejection, not a
//   fetch.
// - Any `crit` is rejected: this module understands no extension.
// - The signature must decode to exactly 64 bytes (JOSE `R || S`) before the
//   platform is called.
// - The payload is parsed only after the signature verifies, so unverified
//   claims never reach a caller.
//
// Rejections are a closed set of this module's own literals, so a caller can
// say why a token was refused without reflecting attacker-supplied text into a
// message a host app is likely to log.

import {
  nativeVerifyPrepareReceiptSignature,
  requireDaaRegistrationNative,
} from '../auth/daaRegistrationNative'
import { contractViolation } from '../errors'
import { fromBase64Url } from './base64url'

/**
 * The one algorithm this SDK verifies. Every additional entry is another
 * verification path, so the list holds only ES256.
 */
export const SUPPORTED_JWS_ALGORITHMS: readonly string[] = Object.freeze(['ES256'])

/** JOSE `R || S` for P-256: two 32-byte big-endian scalars. */
export const ES256_SIGNATURE_LENGTH = 64

/** Uncompressed SEC 1 point: `0x04 || X(32) || Y(32)`. */
const X963_LENGTH = 65

/** Header members that carry or locate a key. Never honoured; always rejected. */
const KEY_SOURCING_HEADERS: readonly string[] = Object.freeze(['jwk', 'jku', 'x5u', 'x5c'])

/** A verification key the caller pinned, addressed by its `kid`. */
export type PinnedEs256Key = Readonly<{
  kid: string
  /** Uncompressed P-256 point. The platform validates it is on the curve. */
  publicKeyX963: Uint8Array
}>

export type Es256JwsRejection =
  | 'malformed_compact_serialization'
  | 'malformed_protected_header'
  | 'unsupported_algorithm'
  | 'unexpected_type'
  | 'header_sources_a_key'
  | 'unsupported_critical_header'
  | 'missing_key_id'
  | 'unknown_key_id'
  | 'malformed_signature'
  | 'signature_mismatch'
  | 'malformed_payload'

export type Es256JwsResult =
  | Readonly<{
      verified: true
      protectedHeader: Readonly<Record<string, unknown>>
      payload: Readonly<Record<string, unknown>>
    }>
  | Readonly<{ verified: false; reason: Es256JwsRejection }>

function rejected(reason: Es256JwsRejection): Es256JwsResult {
  return { verified: false, reason }
}

/** Own-property read, so a name on `Object.prototype` never reads as a member. */
export function ownMember(object: Readonly<Record<string, unknown>>, name: string): unknown {
  return Object.prototype.hasOwnProperty.call(object, name) ? object[name] : undefined
}

/** Decode one Base64URL segment as a UTF-8 JSON object, or `null`. */
function decodeJsonObject(segment: string): Record<string, unknown> | null {
  let bytes: Uint8Array
  try {
    bytes = fromBase64Url(segment)
  } catch {
    return null
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
  } catch {
    return null
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return null
  }
  return parsed as Record<string, unknown>
}

/**
 * Index the pinned keys by `kid`.
 *
 * A malformed key set is a configuration error on this side of the boundary,
 * so it throws rather than returning a rejection that would read as a bad token.
 */
function indexPinnedKeys(keys: readonly PinnedEs256Key[]): ReadonlyMap<string, Uint8Array> {
  if (!Array.isArray(keys) || keys.length === 0) {
    throw contractViolation('ES256 verification requires at least one pinned key')
  }
  const byKid = new Map<string, Uint8Array>()
  for (const key of keys) {
    if (typeof key.kid !== 'string' || key.kid.length === 0) {
      throw contractViolation('every pinned ES256 key must have a non-empty kid')
    }
    if (byKid.has(key.kid)) {
      throw contractViolation('pinned ES256 keys must have distinct kids')
    }
    if (
      !(key.publicKeyX963 instanceof Uint8Array) ||
      key.publicKeyX963.length !== X963_LENGTH ||
      key.publicKeyX963[0] !== 0x04
    ) {
      throw contractViolation('every pinned ES256 key must be an uncompressed P-256 point')
    }
    byKid.set(key.kid, key.publicKeyX963)
  }
  return byKid
}

/**
 * Verify a compact JWS (`header.payload.signature`) against pinned P-256 keys.
 *
 * Length bounds are the caller's business: a caller with a contract bound (as
 * the Prepare receipt has) applies it first.
 *
 * @throws DaaError `contract_violation` for a malformed pinned key set, and when
 *   the platform verifier is unavailable or fails — including a pinned key the
 *   platform does not accept as a P-256 point. A token that is merely wrong is
 *   a `{ verified: false }` result, not a throw.
 */
export async function verifyCompactEs256(
  jws: string,
  options: Readonly<{ keys: readonly PinnedEs256Key[]; expectedTyp: string }>,
): Promise<Es256JwsResult> {
  const keysByKid = indexPinnedKeys(options.keys)

  const segments = jws.split('.')
  if (segments.length !== 3) {
    return rejected('malformed_compact_serialization')
  }
  const [encodedHeader, encodedPayload, encodedSignature] = segments as [string, string, string]
  if (encodedHeader === '' || encodedPayload === '' || encodedSignature === '') {
    return rejected('malformed_compact_serialization')
  }

  const header = decodeJsonObject(encodedHeader)
  if (header === null) {
    return rejected('malformed_protected_header')
  }
  for (const name of KEY_SOURCING_HEADERS) {
    if (Object.prototype.hasOwnProperty.call(header, name)) {
      return rejected('header_sources_a_key')
    }
  }
  if (Object.prototype.hasOwnProperty.call(header, 'crit')) {
    return rejected('unsupported_critical_header')
  }
  const algorithm = ownMember(header, 'alg')
  if (typeof algorithm !== 'string' || !SUPPORTED_JWS_ALGORITHMS.includes(algorithm)) {
    return rejected('unsupported_algorithm')
  }
  if (ownMember(header, 'typ') !== options.expectedTyp) {
    return rejected('unexpected_type')
  }
  const kid = ownMember(header, 'kid')
  if (typeof kid !== 'string' || kid.length === 0) {
    return rejected('missing_key_id')
  }
  const publicKeyX963 = keysByKid.get(kid)
  if (publicKeyX963 === undefined) {
    return rejected('unknown_key_id')
  }

  let signature: Uint8Array
  try {
    signature = fromBase64Url(encodedSignature)
  } catch {
    return rejected('malformed_signature')
  }
  if (signature.length !== ES256_SIGNATURE_LENGTH) {
    return rejected('malformed_signature')
  }

  // RFC 7515 §5.2: the signing input is the ASCII of the two encoded segments
  // exactly as received, never re-encoded from the parsed header.
  const signingInput = new TextEncoder().encode(`${encodedHeader}.${encodedPayload}`)
  const verified = await nativeVerifyPrepareReceiptSignature(requireDaaRegistrationNative(), {
    publicKeyX963,
    signingInput,
    signature,
  })
  if (!verified) {
    return rejected('signature_mismatch')
  }

  const payload = decodeJsonObject(encodedPayload)
  if (payload === null) {
    return rejected('malformed_payload')
  }
  return { verified: true, protectedHeader: header, payload }
}
