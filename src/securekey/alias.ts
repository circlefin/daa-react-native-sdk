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

import { DAA_ENVIRONMENTS } from '../config'
import type { DaaEnvironment } from '../config'
import { toBase64Url } from '../crypto/base64url'
import { sha256 } from '../crypto/sha256'
import { contractViolation } from '../errors'
import { isUuid } from '../validation/uuid'
import type { OwnerKeyIdentity } from './SecureKey'

// The installation key namespace. This value is interpolated into an OS keystore
// identifier (iOS `kSecAttrApplicationTag`, Android KeyStore alias), so ALL
// THREE inputs are validated — it is a custody-key namespace, not free text,
// and a store can be constructed without going through DaaClient's checks.
//
// Validating `environment` against the allow-list is what keeps the alias
// injective on that axis: no allowed environment contains `.`, so splitting
// from the right always recovers it (see `parseSecureKeyAlias`).
//
// The per-Owner component is a SHA-256 digest, never the raw
// `clientEntityId` — see `deriveKeyScope`. Hashing also keeps a
// string-concatenation collision out of the `clientEntityId` axis: recovering
// two different `(appId, environment, clientEntityId)` triples from one alias
// would require a SHA-256 preimage or collision, not a parsing ambiguity.
const APP_ID_CHARSET = /^[A-Za-z0-9._-]+$/

// 128 bits of digest is enough collision resistance for a per-installation,
// per-Owner namespace while leaving room in native's 64-character appId slot
// for a real-world appId. Base64URL length is computed rather than hardcoded
// so it can never drift from KEY_SCOPE_DIGEST_BYTES.
const KEY_SCOPE_DIGEST_BYTES = 16
const KEY_SCOPE_LENGTH = Math.ceil((KEY_SCOPE_DIGEST_BYTES * 8) / 6) // 22

// Native's hard cap on the appId slot (`isValidNamespace` in daa-ios-sdk's
// DaaSecureKey.swift: `[A-Za-z0-9._-]{1,64}`). The value that actually reaches
// it is `${appId}.${keyScope}` (see `secureKeyAlias`), so this cap applies to
// the COMPOSED value, and only `parseSecureKeyAlias` — which recovers that
// composed value — validates against it.
const MAX_NATIVE_APP_ID_LENGTH = 64

// What a consumer may actually configure as `appId`: native's slot minus the
// per-Owner scope and its separator. Derived from the two constants above
// rather than written as 41, so the limit enforced at the door can never drift
// from the composed value's real budget.
//
// Enforcing this in `assertAppId` is what keeps the two checks from
// disagreeing: an over-long appId is rejected up front, naming the limit the
// consumer controls, instead of passing validation and failing later during
// key resolution with a budget the caller never saw.
const MAX_APP_ID_LENGTH = MAX_NATIVE_APP_ID_LENGTH - 1 - KEY_SCOPE_LENGTH // 41

/**
 * The per-Owner key-scope component: unpadded Base64URL of the
 * first 128 bits of SHA-256 over `appId`, `environment`, and `clientEntityId`.
 *
 * The preimage deliberately includes `appId` and `environment`, not
 * `clientEntityId` alone, so the digest cannot be correlated across
 * applications or environments for the same Owner.
 *
 * `appId`, `environment`, and `clientEntityId` are joined with a NUL (`\0`)
 * separator. NUL cannot appear in any of the three — `APP_ID_CHARSET` excludes
 * control characters, `environment` is one of the fixed `DAA_ENVIRONMENTS`
 * strings, and `clientEntityId` is validated as a hyphenated UUID — so the
 * join cannot map two different triples onto the same preimage bytes.
 */
export function deriveKeyScope(identity: OwnerKeyIdentity): string {
  const preimage = `${identity.appId}\u0000${identity.environment}\u0000${identity.clientEntityId}`
  const digest = sha256(new TextEncoder().encode(preimage))
  return toBase64Url(digest.subarray(0, KEY_SCOPE_DIGEST_BYTES))
}

/**
 * What actually reaches the native module's `appId` parameter once
 * `parseSecureKeyAlias` recovers it: the consumer's configured `appId`
 * composed with the derived per-Owner {@link deriveKeyScope} digest — NOT
 * `OwnerKeyIdentity.appId` alone.
 *
 * Kept as its own type, rather than reusing or widening `OwnerKeyIdentity`,
 * so the consumer's raw `appId` and the opaque scoped value native receives
 * are never silently conflated. `environment` is unchanged, since
 * it is not namespaced by Owner.
 */
export type NativeKeyIdentity = Readonly<{
  appId: string
  environment: DaaEnvironment
}>

/**
 * Build the RN secure-key alias: `{appId}.{keyScope}.{environment}`, where
 * `keyScope` is {@link deriveKeyScope}'s digest of `identity`.
 *
 * `keyScope` is composed with `appId` in the slot native validates and stores
 * against — the derived scope, not `identity.clientEntityId` and not
 * `identity.appId` by itself, is what reaches the native module (see
 * {@link NativeKeyIdentity}). Two different Owners (`clientEntityId`) on the
 * same `{appId, environment}` therefore resolve to two different aliases, and
 * so to two different native keys. A returning Owner reproduces the same
 * digest and so the same alias, and therefore resolves the SAME native key.
 */
export function secureKeyAlias(identity: OwnerKeyIdentity): string {
  assertAppId(identity.appId)
  const environment = parseEnvironment(identity.environment)
  assertClientEntityId(identity.clientEntityId)
  const keyScope = deriveKeyScope(identity)
  // No length check is needed here: `assertAppId` caps `appId` at
  // MAX_APP_ID_LENGTH, which is defined as exactly the room left once the
  // separator and the fixed-width `keyScope` are accounted for, so the
  // composed value cannot exceed MAX_NATIVE_APP_ID_LENGTH.
  const nativeAppId = `${identity.appId}.${keyScope}`
  return `${nativeAppId}.${environment}`
}

/**
 * Inverse of `secureKeyAlias`'s environment split — NOT a full inverse of
 * `secureKeyAlias`, because {@link deriveKeyScope} is one-way. Splits from the
 * right so the composed `{appId}.{keyScope}` prefix may itself contain dots
 * (an `appId` always could). The Expo module then constructs native
 * `DaaAuthKeyIdentity` from these fields plus a per-install UUID the native
 * module owns.
 *
 * Returns {@link NativeKeyIdentity}, not `OwnerKeyIdentity`: what this
 * recovers is the value native's `appId` parameter needs — the composed
 * scope — not the consumer's original `appId` and not the `clientEntityId`
 * that fed into it. That information is exactly what the hash discards, by
 * design.
 */
export function parseSecureKeyAlias(alias: string): NativeKeyIdentity {
  const separator = alias.lastIndexOf('.')
  if (separator <= 0 || separator === alias.length - 1) {
    throw contractViolation(
      `secure-key alias must be {appId}.{environment} (got a ${alias.length}-char value)`,
    )
  }
  const appId = alias.slice(0, separator)
  const environment = parseEnvironment(alias.slice(separator + 1))
  assertNativeAppId(appId)
  return { appId, environment }
}

/**
 * Validates the consumer-supplied `appId`, before the per-Owner scope is
 * folded in — so the cap is MAX_APP_ID_LENGTH, not native's slot size.
 *
 * Exported for `DaaClient`'s constructor, so an `appId` no key can be stored
 * under is refused before any request is sent, not on the first key
 * resolution — which comes after Social Session has already bound the end
 * user. `secureKeyAlias` still checks it, because a store can be reached
 * without a `DaaClient`.
 */
export function assertAppId(appId: string): void {
  assertAppIdWithin(appId, MAX_APP_ID_LENGTH)
}

/**
 * Validates the composed `{appId}.{keyScope}` recovered from an alias, which
 * is what native's appId slot actually receives — so the cap here is native's
 * full MAX_NATIVE_APP_ID_LENGTH. Applying assertAppId's tighter consumer cap
 * would reject legitimate aliases, since the scope alone is 22 characters.
 */
function assertNativeAppId(nativeAppId: string): void {
  assertAppIdWithin(nativeAppId, MAX_NATIVE_APP_ID_LENGTH)
}

function assertAppIdWithin(value: string, maxLength: number): void {
  // Report only the length, never the (untrusted) value, so it cannot forge log
  // lines when the error surfaces.
  if (!APP_ID_CHARSET.test(value) || value.length > maxLength) {
    throw contractViolation(
      `appId must match ${String(APP_ID_CHARSET)} and be at most ${maxLength} ` +
        `characters to namespace the secure key (got a ${value.length}-char value)`,
    )
  }
}

function assertClientEntityId(clientEntityId: string): void {
  if (!isUuid(clientEntityId)) {
    throw contractViolation('clientEntityId must be a UUID to namespace the secure key')
  }
}

function parseEnvironment(value: string): DaaEnvironment {
  for (const environment of DAA_ENVIRONMENTS) {
    if (environment === value) {
      return environment
    }
  }
  throw contractViolation(`unknown environment; expected one of ${DAA_ENVIRONMENTS.join(', ')}`)
}
