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

// Device Registration Complete dual-header proofs.
//
// Complete sends two JWSs, in two headers:
//
//   X-Registration-Flow-Authorization  typ=daa-registration-flow-authorization+jws
//   X-Device-Authorization             typ=daa-device-authorization+jws
//
// Both embed the signer's P-256 public JWK (no trusted server `kid`) and both
// carry the request claims — discriminator, schema_version, aud, method,
// canonical_path, body digest, idempotency_key, jti, iat, exp — with the same
// values, except `jti`, which must differ between the two proofs.
//
// The two claim sets are NOT the same. The flow proof alone also carries the
// binding claims: the registration handle digest, profile_id (the session's
// clientEntityId), the submitted AuthKey's thumbprint, and the code-verifier
// digest. The device proof carries only the request claims above. It proves
// that the holder of the AuthKey in its embedded JWK signed this exact
// request; the flow proof's `auth_key_thumbprint` is what binds that AuthKey
// to the registration attempt. DAA decodes the device proof's claims
// strictly and rejects any field outside that set, so adding a binding claim
// to the device proof makes Complete fail. Keep the two builders separate.
// Native's registration validator (`DaaRegistrationAuthorizationSigningInput`)
// must accept this request-claims-only device payload: a native SDK that
// requires the binding claims refuses to sign it, and Complete fails on device
// before any request is sent.
//
// The only bytes each key signs are its own JWS signing input. This module is
// not exported from `index.ts`.
//
// The two proofs sign through two DIFFERENT seams on purpose, even though both
// signing inputs are built by the same `compactJws`. The flow proof signs via
// `RegistrationFlowKey` (see that module — it has its own native path). The
// device proof signs via `OwnerAuthKey.signRegistrationDeviceAuthorization`,
// NOT `signExactBytes`:
// `signExactBytes` reaches native `signDeviceAuthorization`, which is the
// post-activation seam (`auth/deviceAuthorization.ts`) and validates against a
// different `typ`, a `kid`-only header, and a different claim set. Signing the
// registration device proof through that seam would validate cleanly in this
// SDK's own JWS construction but fail on native's real validator. Keep the two
// seams separate; see `securekey/SecureKey.ts`.

import { fromBase64Url, toBase64Url } from '../crypto/base64url'
import { p256JwkThumbprint, p256PublicJwkFromSpki } from '../crypto/jwkThumbprint'
import { randomUuidV4 } from '../crypto/random'
import { sha256 } from '../crypto/sha256'
import { contractViolation, mapNativeError } from '../errors'
import type { RegistrationFlowKey } from './RegistrationFlowKey'
import type { OwnerAuthKey } from '../securekey/SecureKey'
import { isUuid } from '../validation/uuid'
import { registrationCodeChallengeS256 } from './registrationCodeVerifier'

export const REGISTRATION_FLOW_AUTHORIZATION_HEADER = 'X-Registration-Flow-Authorization'
export const REGISTRATION_DEVICE_AUTHORIZATION_HEADER = 'X-Device-Authorization'

/** Public path of `completeDeviceRegistration` (OpenAPI + signed `canonical_path`). */
export const DEVICE_REGISTRATION_COMPLETE_PATH = '/v1/accounts/auth/deviceKeyRegistration'

const FLOW_TYP = 'daa-registration-flow-authorization+jws'
const DEVICE_TYP = 'daa-device-authorization+jws'
const AUDIENCE = 'circle-digital-asset-accounts'
const JOSE_SIGNATURE_LENGTH = 64
/** Verifier ceiling: `exp - iat` must be at most 300 seconds. */
const AUTHORIZATION_LIFETIME_SECONDS = 300
/** The closed discriminator/schema-version pair DAA accepts. */
const DISCRIMINATOR = 'device_key_registration.v1'
const SCHEMA_VERSION = 1

export type RegistrationAuthorizationClock = Readonly<{
  nowEpochSeconds: () => number
  jti: () => string
}>

const DEFAULT_CLOCK: RegistrationAuthorizationClock = {
  nowEpochSeconds: () => Math.floor(Date.now() / 1000),
  jti: randomUuidV4,
}

export type RegistrationCompleteProofs = Readonly<{
  flowJws: string
  deviceJws: string
}>

export type RegistrationCompleteAuthorizationRequest = Readonly<{
  bodyBytes: Uint8Array
  registrationHandle: string
  registrationCodeVerifier: string
  /** The bound Owner's durable identifier; signed as `profile_id`. */
  clientEntityId: string
  flowKey: RegistrationFlowKey
  authKey: OwnerAuthKey
}>

/**
 * Build the two registration JWSs over the exact Complete body bytes.
 *
 * Serializes header and payload with `JSON.stringify` (DAA verifies the
 * transmitted signing input and parsed claim semantics, not a reconstructed
 * encoding). Each signature is 64-byte JOSE `R || S`.
 */
export async function authorizeRegistrationComplete(
  request: RegistrationCompleteAuthorizationRequest,
  clock: RegistrationAuthorizationClock = DEFAULT_CLOCK,
): Promise<RegistrationCompleteProofs> {
  const idempotencyKey = idempotencyKeyFromExactBody(request.bodyBytes)
  if (idempotencyKey === undefined) {
    throw contractViolation(
      'Device Registration Complete body must contain idempotencyKey so both proofs bind it',
    )
  }
  if (!isUuid(request.clientEntityId)) {
    throw contractViolation('clientEntityId must be a UUID')
  }

  const iat = requireEpochSeconds(clock.nowEpochSeconds())
  const flowJti = clock.jti()
  const deviceJti = clock.jti()
  if (!isUuid(flowJti) || !isUuid(deviceJti)) {
    throw contractViolation('jti must be a UUID')
  }

  const flowSpki = fromBase64Url(await request.flowKey.publicKeySpkiBase64Url())
  const authSpki = fromBase64Url(await request.authKey.publicKeySpkiBase64Url())
  const authKeyThumbprint = p256JwkThumbprint(authSpki)
  const requestClaimInputs = { bodyBytes: request.bodyBytes, idempotencyKey, iat }

  const flowJws = await compactJws({
    protectedHeader: {
      alg: 'ES256',
      jwk: p256PublicJwkFromSpki(flowSpki),
      typ: FLOW_TYP,
    },
    payload: registrationFlowClaims({
      ...requestClaimInputs,
      registrationHandle: request.registrationHandle,
      registrationCodeVerifier: request.registrationCodeVerifier,
      clientEntityId: request.clientEntityId,
      authKeyThumbprint,
      jti: flowJti,
    }),
    sign: (bytes) => request.flowKey.signExactBytes(bytes),
  })
  const deviceJws = await compactJws({
    protectedHeader: {
      alg: 'ES256',
      jwk: p256PublicJwkFromSpki(authSpki),
      typ: DEVICE_TYP,
    },
    // Request claims only — no binding claims (see the header comment).
    payload: registrationDeviceClaims({ ...requestClaimInputs, jti: deviceJti }),
    // Registration, not post-activation: this AuthKey has not been
    // acknowledged yet, and the claim/typ shape here is the registration
    // profile, not `auth/deviceAuthorization.ts`'s. Routing this through
    // `signExactBytes` would sign valid bytes with the wrong native
    // validator (`DaaDeviceAuthorizationSigningInput`, which pins the
    // post-activation `typ` and a `kid`-only header) and fail on a real
    // device. `signRegistrationDeviceAuthorization` is the distinct seam for
    // this profile — see `securekey/SecureKey.ts`.
    sign: (bytes) => request.authKey.signRegistrationDeviceAuthorization(bytes),
  })
  return { flowJws, deviceJws }
}

async function compactJws(args: {
  protectedHeader: object
  payload: object
  sign: (bytes: Uint8Array) => Promise<Uint8Array>
}): Promise<string> {
  const signingInput =
    toBase64Url(utf8Json(args.protectedHeader)) + '.' + toBase64Url(utf8Json(args.payload))
  let signature: Uint8Array
  try {
    signature = await args.sign(new TextEncoder().encode(signingInput))
  } catch (err) {
    throw mapNativeError(err)
  }
  if (signature.length !== JOSE_SIGNATURE_LENGTH) {
    throw contractViolation('registration authorization signature must be 64 bytes')
  }
  return signingInput + '.' + toBase64Url(signature)
}

type RequestClaimInputs = {
  bodyBytes: Uint8Array
  idempotencyKey: string
  jti: string
  iat: number
}

/**
 * The claims that pin the request: operation, body, idempotency key, path,
 * method, and audience. Both payloads open with these, in this order.
 */
function requestTargetClaims(args: RequestClaimInputs): object {
  return {
    discriminator: DISCRIMINATOR,
    schema_version: SCHEMA_VERSION,
    body_sha256: toBase64Url(sha256(args.bodyBytes)),
    idempotency_key: args.idempotencyKey,
    canonical_path: DEVICE_REGISTRATION_COMPLETE_PATH,
    method: 'POST',
    aud: AUDIENCE,
  }
}

/** Replay and lifetime claims. Both payloads close with these. */
function lifetimeClaims(args: RequestClaimInputs): object {
  return {
    jti: args.jti,
    iat: args.iat,
    exp: args.iat + AUTHORIZATION_LIFETIME_SECONDS,
  }
}

/** Flow proof: the 10 request claims plus the four binding claims. */
function registrationFlowClaims(
  args: RequestClaimInputs & {
    registrationHandle: string
    registrationCodeVerifier: string
    clientEntityId: string
    authKeyThumbprint: string
  },
): object {
  return {
    ...requestTargetClaims(args),
    registration_handle_sha256: toBase64Url(
      sha256(new TextEncoder().encode(args.registrationHandle)),
    ),
    profile_id: args.clientEntityId,
    auth_key_thumbprint: args.authKeyThumbprint,
    code_verifier_sha256: registrationCodeChallengeS256(args.registrationCodeVerifier),
    ...lifetimeClaims(args),
  }
}

/**
 * Device proof: the 10 request claims only. DAA rejects any other
 * field here, so the binding claims must never be added.
 */
function registrationDeviceClaims(args: RequestClaimInputs): object {
  return {
    ...requestTargetClaims(args),
    ...lifetimeClaims(args),
  }
}

function requireEpochSeconds(value: number): number {
  if (!Number.isInteger(value) || value <= 0) {
    throw contractViolation('registration authorization clock must yield a positive Unix timestamp')
  }
  return value
}

/**
 * Read `idempotencyKey` from the already-serialized body. Parsing is observation
 * only — the hashed and sent bytes are unchanged.
 */
function idempotencyKeyFromExactBody(bodyBytes: Uint8Array): string | undefined {
  if (bodyBytes.length === 0) {
    return undefined
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bodyBytes))
  } catch {
    throw contractViolation('signed request body is not UTF-8 JSON')
  }
  if (!isJsonObject(parsed)) {
    throw contractViolation('signed request body must be a JSON object')
  }
  if (!Object.prototype.hasOwnProperty.call(parsed, 'idempotencyKey')) {
    return undefined
  }

  const value = parsed.idempotencyKey
  if (typeof value !== 'string' || !isUuid(value)) {
    throw contractViolation('idempotencyKey must be a UUID when present on a signed body')
  }
  return value
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function utf8Json(value: object): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(value))
}
