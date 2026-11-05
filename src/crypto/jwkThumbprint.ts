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

import { toBase64Url } from './base64url'
import { contractViolation } from '../errors'
import { sha256 } from './sha256'

// RFC 7638 JWK thumbprint (`jkt`) of a P-256 public key, derived from its DER
// SubjectPublicKeyInfo. Deriving it in ONE place means the in-memory and native
// stores agree byte-for-byte, and — because `x`/`y` are the fixed 32-byte field
// elements sliced straight from the SPKI — the short-coordinate interop bug
// (a `jkt` computed over a leading-zero-trimmed coordinate) cannot occur.
//
// A P-256 SPKI is exactly 91 bytes and ends with a 65-byte uncompressed point
// (`0x04 || X(32) || Y(32)`) starting at offset 26.

/** P-256 public JWK as Registration Complete embeds it (`kty`/`crv`/`x`/`y`). */
export type P256PublicJwk = Readonly<{
  kty: 'EC'
  crv: 'P-256'
  x: string
  y: string
}>

/**
 * Slice the uncompressed P-256 point out of a 91-byte SPKI.
 *
 * Used both for RFC 7638 thumbprints and for the embedded `jwk` in the
 * registration dual-header JWSs. One slice, so those two cannot disagree.
 */
export function p256PublicJwkFromSpki(spki: Uint8Array): P256PublicJwk {
  if (spki.length !== 91 || spki[26] !== 0x04) {
    // contract_violation (not a raw Error) so callers narrowing with isDaaError
    // catch this on the production thumbprint() path too.
    throw contractViolation('expected a 91-byte P-256 SPKI with an uncompressed point')
  }
  return {
    kty: 'EC',
    crv: 'P-256',
    x: toBase64Url(spki.subarray(27, 59)),
    y: toBase64Url(spki.subarray(59, 91)),
  }
}

export function p256JwkThumbprint(spki: Uint8Array): string {
  const jwk = p256PublicJwkFromSpki(spki)
  // Canonical JWK: members in lexicographic order, no whitespace (RFC 7638).
  const canonical = `{"crv":"P-256","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`
  return toBase64Url(sha256(new TextEncoder().encode(canonical)))
}
