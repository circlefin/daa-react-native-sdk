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

// Registered-device authorization: a compact ES256 JWS in
// `X-Device-Authorization`, bound to the exact body bytes that will be sent.
//
// This is the post-activation header (`typ` in DEVICE_AUTHORIZATION_TYP).
// The SDK signs Device Registration Complete with its own two-JWS profile
// (`auth/registrationAuthorization.ts`), with its own `typ` values and header
// set. This module also maps the registry's `register_device_key` operation
// and accepts a not-yet-registered (`created`) AuthKey for that operation only;
// no SDK client signs it through this module. Not a public generic
// `sign(bytes)`.
// The only bytes the AuthKey signs are this JWS signing input.
//
// Operation identity is the digest-pinned Owner-authorization registry:
// `discriminator` + `schema_version` are the lookup key. The verifier resolves
// method and `canonical_path` from that entry; it does not infer the operation
// from the path. Callers name one of the six closed operations — they cannot
// pass a free-form `/v1` path.
//
// The header carries the published `typ` (`aw-device-authorization+jws`).
//
// Production `OwnerAuthKey.signExactBytes` reaches native
// `signDeviceAuthorization` via the Expo bridge. Tests use
// `InMemorySecureKeyStore`. The create-account, transfer, and withdrawal
// clients reach this through `api/signedResource.ts` rather than calling it
// directly.

import { toBase64Url } from '../crypto/base64url'
import { randomUuidV4 } from '../crypto/random'
import { sha256 } from '../crypto/sha256'
import { contractViolation, mapNativeError } from '../errors'
import type { OwnerAuthKey } from '../securekey/SecureKey'
import { isUuid } from '../validation/uuid'

export const DEVICE_AUTHORIZATION_HEADER = 'X-Device-Authorization'

const DEVICE_AUTHORIZATION_TYP = 'aw-device-authorization+jws'
const DEVICE_AUTHORIZATION_AUD = 'circle-digital-asset-accounts'
const JOSE_SIGNATURE_LENGTH = 64
/** Verifier ceiling: `exp - iat` must be at most 300 seconds. */
const AUTHORIZATION_LIFETIME_SECONDS = 300
const SCHEMA_VERSION = 1

/**
 * Closed Owner-authorization registry (v1). Wire `discriminator` values from
 * the registry schema.
 */
export type DeviceAuthorizationOperation =
  | 'create_account'
  | 'transfer'
  | 'withdrawal'
  | 'complete_social_login'
  | 'get_device_context'
  | 'register_device_key'

export type DeviceAuthorizationProfile = Readonly<{
  discriminator: DeviceAuthorizationOperation
  schemaVersion: typeof SCHEMA_VERSION
  method: 'GET' | 'POST'
  canonicalPath: string
}>

export type DeviceAuthorizationRequest = Readonly<{
  authKey: OwnerAuthKey
  /** Proposed `AuthKey` id at Complete, or `DeviceContext.authKeyId` after ACTIVE. */
  authKeyId: string
  operation: DeviceAuthorizationOperation
  /** Exact bytes that will be hashed and sent. Empty array for a bodyless call. */
  bodyBytes: Uint8Array
}>

/**
 * Test-only clock. Production code always uses the system clock. This
 * module is not on the public `.` entry, and `postSignedResource` does not
 * take a clock. `authorizeExactRequest` accepts one so tests can pin `iat`/`jti`.
 */
export type DeviceAuthorizationClock = Readonly<{
  nowEpochSeconds: () => number
  jti: () => string
}>

const DEFAULT_CLOCK: DeviceAuthorizationClock = {
  nowEpochSeconds: () => Math.floor(Date.now() / 1000),
  jti: randomUuidV4,
}

/** Registry profile for one closed operation. Method and path are not caller-chosen. */
export function deviceAuthorizationProfile(
  operation: DeviceAuthorizationOperation,
): DeviceAuthorizationProfile {
  switch (operation) {
    case 'create_account':
      return {
        discriminator: 'create_account',
        schemaVersion: SCHEMA_VERSION,
        method: 'POST',
        canonicalPath: '/v1/accounts',
      }
    case 'transfer':
      return {
        discriminator: 'transfer',
        schemaVersion: SCHEMA_VERSION,
        method: 'POST',
        canonicalPath: '/v1/accounts/transfers',
      }
    case 'withdrawal':
      return {
        discriminator: 'withdrawal',
        schemaVersion: SCHEMA_VERSION,
        method: 'POST',
        canonicalPath: '/v1/accounts/withdrawals',
      }
    case 'complete_social_login':
      return {
        discriminator: 'complete_social_login',
        schemaVersion: SCHEMA_VERSION,
        method: 'POST',
        canonicalPath: '/v1/accounts/auth/sessions',
      }
    case 'get_device_context':
      return {
        discriminator: 'get_device_context',
        schemaVersion: SCHEMA_VERSION,
        method: 'GET',
        canonicalPath: '/v1/accounts/auth/context',
      }
    case 'register_device_key':
      return {
        discriminator: 'register_device_key',
        schemaVersion: SCHEMA_VERSION,
        method: 'POST',
        canonicalPath: '/v1/accounts/auth/deviceKeyRegistration',
      }
    default: {
      const exhaustive: never = operation
      void exhaustive
      throw contractViolation('device authorization operation is not in the closed registry')
    }
  }
}

/**
 * Build a compact ES256 JWS over the exact request bytes.
 *
 * Serializes the protected header and payload with `JSON.stringify` (DAA
 * verifies the transmitted signing input and parsed claim semantics, not a
 * reconstructed JSON encoding). Signs the compact signing input
 * `base64url(header) + "." + base64url(payload)` and appends a 64-byte JOSE
 * `R || S` signature.
 */
export async function authorizeExactRequest(
  request: DeviceAuthorizationRequest,
  clock: DeviceAuthorizationClock = DEFAULT_CLOCK,
): Promise<string> {
  // `register_device_key` accepts a `created` AuthKey. Other operations
  // require a registered key. `typ` lives in DEVICE_AUTHORIZATION_TYP, not at
  // each call site.
  if (request.operation !== 'register_device_key' && request.authKey.resolution() !== 'existing') {
    throw contractViolation('X-Device-Authorization requires a registered AuthKey')
  }
  if (!isUuid(request.authKeyId)) {
    throw contractViolation('authKeyId must be a UUID')
  }

  const profile = deviceAuthorizationProfile(request.operation)
  const idempotencyKey = idempotencyKeyFromExactBody(request.bodyBytes)
  const iat = requireEpochSeconds(clock.nowEpochSeconds())
  const jti = clock.jti()
  if (!isUuid(jti)) {
    throw contractViolation('jti must be a UUID')
  }

  const protectedHeader = {
    alg: 'ES256',
    kid: request.authKeyId,
    typ: DEVICE_AUTHORIZATION_TYP,
  }
  const payload = payloadClaims({
    bodyBytes: request.bodyBytes,
    profile,
    idempotencyKey,
    jti,
    iat,
  })

  const signingInput = toBase64Url(utf8Json(protectedHeader)) + '.' + toBase64Url(utf8Json(payload))
  const signature = await signSigningInput(request.authKey, signingInput)
  return signingInput + '.' + toBase64Url(signature)
}

function payloadClaims(args: {
  bodyBytes: Uint8Array
  profile: DeviceAuthorizationProfile
  idempotencyKey: string | undefined
  jti: string
  iat: number
}): object {
  const bodySha256 = toBase64Url(sha256(args.bodyBytes))
  const exp = args.iat + AUTHORIZATION_LIFETIME_SECONDS
  if (args.idempotencyKey === undefined) {
    return {
      body_sha256: bodySha256,
      canonical_path: args.profile.canonicalPath,
      method: args.profile.method,
      aud: DEVICE_AUTHORIZATION_AUD,
      discriminator: args.profile.discriminator,
      schema_version: args.profile.schemaVersion,
      jti: args.jti,
      iat: args.iat,
      exp,
    }
  }
  return {
    body_sha256: bodySha256,
    idempotency_key: args.idempotencyKey,
    canonical_path: args.profile.canonicalPath,
    method: args.profile.method,
    aud: DEVICE_AUTHORIZATION_AUD,
    discriminator: args.profile.discriminator,
    schema_version: args.profile.schemaVersion,
    jti: args.jti,
    iat: args.iat,
    exp,
  }
}

async function signSigningInput(authKey: OwnerAuthKey, signingInput: string): Promise<Uint8Array> {
  let signature: Uint8Array
  try {
    signature = await authKey.signExactBytes(new TextEncoder().encode(signingInput))
  } catch (err) {
    throw mapNativeError(err)
  }
  if (signature.length !== JOSE_SIGNATURE_LENGTH) {
    throw contractViolation('device authorization signature must be 64 bytes')
  }
  return signature
}

function requireEpochSeconds(value: number): number {
  if (!Number.isInteger(value) || value <= 0) {
    throw contractViolation('device authorization clock must yield a positive Unix timestamp')
  }
  return value
}

/**
 * Read `idempotencyKey` from the already-serialized body. Parsing is observation
 * only — the hashed and sent bytes are unchanged.
 *
 * Include `idempotency_key` iff the JSON body contains `idempotencyKey`,
 * and omit it for a bodyless request.
 *
 * Exported so `api/signedResource.ts` can recover the same key when mapping a
 * `409` `IDEMPOTENCY_KEY_REUSED` failure, rather than parsing the body a
 * second, independent way.
 */
export function idempotencyKeyFromExactBody(bodyBytes: Uint8Array): string | undefined {
  if (bodyBytes.length === 0) {
    return undefined
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bodyBytes))
  } catch {
    throw contractViolation('signed request body is not UTF-8 JSON')
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw contractViolation('signed request body must be a JSON object')
  }
  if (!Object.prototype.hasOwnProperty.call(parsed, 'idempotencyKey')) {
    return undefined
  }

  const value = (parsed as Record<string, unknown>).idempotencyKey
  if (typeof value !== 'string' || !isUuid(value)) {
    throw contractViolation('idempotencyKey must be a UUID when present on a signed body')
  }
  return value
}

function utf8Json(value: object): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(value))
}
