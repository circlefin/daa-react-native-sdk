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

// Signed public POST/GET: either serialize-once body bytes, or no body at all,
// plus a fresh `X-Device-Authorization` compact JWS.
//
// Signed v1 operations carry `query = null`. Failures are classified on the
// numeric DAA status code only, through `wire/daaStatusCodes.ts`.
// An invalid, missing, replayed, or mismatched authorization becomes
// `contract_violation`. A `409` whose body carries `IDEMPOTENCY_KEY_REUSED`
// (`420034`) becomes `idempotency_conflict`, with the key recovered from the
// same request bytes that were signed and sent, not the (unsigned) response
// body; the caller reconciles the original operation rather than replacing the
// key.
//
// DAA has no code for an expired device authorization, a missing one, or a
// revoked credential: it reports them as `DEVICE_AUTHORIZATION_INVALID` or,
// on context refresh, `DEVICE_AUTHORIZATION_REQUEST_MISMATCH`, and the SDK
// classifies the code it receives. So a signed call is sent once, with no
// fresh-JWS retry, and no DAA response produces `device_revoked`. A
// non-numeric string `code` is `api`, even when it is the name of one of these
// conditions or of a row this mapping classifies.
//
// `AccountsClient.create` (`create_account`),
// `TransfersClient.create` (`transfer`), and `WithdrawalsClient.create`
// (`withdrawal`) call `postSignedResource`. `DaaUserClient.refreshContext`
// (`get_device_context`) calls `getSignedResource` — the device-authorization
// contract treats "signed context refresh" alongside protected writes, and
// `securekey/SecureKey.ts` lists it alongside them as one of the defined DAA
// operations signing is reachable for.

import {
  authorizeExactRequest,
  DEVICE_AUTHORIZATION_HEADER,
  deviceAuthorizationProfile,
  idempotencyKeyFromExactBody,
  type DeviceAuthorizationOperation,
} from '../auth/deviceAuthorization'
import { apiFailure, contractViolation, idempotencyConflict, type DaaError } from '../errors'
import type { OwnerAuthKeyResolver } from '../securekey/ownerAuthKeyResolver'
import type { OwnerAuthKey } from '../securekey/SecureKey'
import type { DaaHttpResponse, DaaTransport } from '../transport/DaaTransport'
import { headerValueIgnoringCase } from '../transport/headers'
import { isDaaStatus } from '../wire/daaStatusCodes'
import { readDaaStatusCode } from '../wire/errorEnvelope'
import { decodeResourceResponse } from './resourceRequest'

/**
 * What a resource client needs to authorize a signed write: the same pair
 * `postSignedResource` takes, except the key is resolved when a write is
 * actually made rather than held from the moment `forUser` returns.
 *
 * The two halves come from the same `ACTIVE` Device Registration Complete.
 * `authKeyId` is the `DeviceContext` value the service assigned; the key itself
 * is enclave-held and is not a field on that decoded result, so it is
 * re-resolved by the `{appId, environment, clientEntityId}` alias login
 * already used.
 *
 * Passed as one required value, because the failure this prevents is
 * `DaaClient.forUser` validating a user context and then building the
 * operations surface without it — leaving every write with nothing to sign
 * with. A required constructor parameter makes that omission a compile error.
 *
 * Not on the public entry. A consumer holding one could reach
 * `OwnerAuthKey.signExactBytes`, which is the generic signing surface this SDK
 * deliberately does not expose.
 */
export type DaaUserSigning = Readonly<{
  /** Resolves the installation AuthKey. Signing fails closed until it is registered. */
  resolveAuthKey: OwnerAuthKeyResolver
  /** `DeviceContext.authKeyId`, which becomes the authorization JWS `kid`. */
  authKeyId: string
}>

export type PostSignedResourceOptions<T> = Readonly<{
  transport: DaaTransport
  operation: DeviceAuthorizationOperation
  authKey: OwnerAuthKey
  authKeyId: string
  /** Final serialized bytes. Hashed and sent as this same slice. */
  bodyBytes: Uint8Array
  expectedStatus: number
  decode: (value: unknown) => T
}>

/** Execute a public POST with a fresh registered-device authorization header. */
export async function postSignedResource<T>({
  transport,
  operation,
  authKey,
  authKeyId,
  bodyBytes,
  expectedStatus,
  decode,
}: PostSignedResourceOptions<T>): Promise<T> {
  const profile = deviceAuthorizationProfile(operation)
  if (profile.method !== 'POST') {
    throw contractViolation('postSignedResource only sends POST registry operations')
  }

  const response = await sendSignedPost({
    transport,
    operation,
    path: profile.canonicalPath,
    authKey,
    authKeyId,
    bodyBytes,
  })

  if (response.status !== expectedStatus) {
    throw mapSignedRequestFailure(response, bodyBytes)
  }
  return decodeResourceResponse({ response, expectedStatus, decode })
}

export type GetSignedResourceOptions<T> = Readonly<{
  transport: DaaTransport
  operation: DeviceAuthorizationOperation
  authKey: OwnerAuthKey
  authKeyId: string
  expectedStatus: number
  decode: (value: unknown) => T
}>

/** No body to serialize for a bodyless signed read; the signature hashes the empty byte array. */
const EMPTY_BODY = new Uint8Array(0)

/**
 * Execute a public GET with a fresh registered-device authorization header.
 *
 * The only registry operation this reaches is `get_device_context`
 * (`DaaUserClient.refreshContext`). There is no request body to serialize or
 * sign over: `authorizeExactRequest` hashes the empty byte array per the
 * bodyless-request rule, and nothing is sent as a request entity — the same
 * bodyless shape `resourceRequest.ts`'s unsigned `readResource` sends.
 */
export async function getSignedResource<T>({
  transport,
  operation,
  authKey,
  authKeyId,
  expectedStatus,
  decode,
}: GetSignedResourceOptions<T>): Promise<T> {
  const profile = deviceAuthorizationProfile(operation)
  if (profile.method !== 'GET') {
    throw contractViolation('getSignedResource only sends GET registry operations')
  }

  const response = await sendSignedGet({
    transport,
    operation,
    path: profile.canonicalPath,
    authKey,
    authKeyId,
  })

  if (response.status !== expectedStatus) {
    throw mapSignedRequestFailure(response, EMPTY_BODY)
  }
  return decodeResourceResponse({ response, expectedStatus, decode })
}

async function sendSignedGet(args: {
  transport: DaaTransport
  operation: DeviceAuthorizationOperation
  path: string
  authKey: OwnerAuthKey
  authKeyId: string
}): Promise<DaaHttpResponse> {
  const compactJws = await authorizeExactRequest({
    authKey: args.authKey,
    authKeyId: args.authKeyId,
    operation: args.operation,
    bodyBytes: EMPTY_BODY,
  })
  return args.transport.send({
    method: 'GET',
    path: args.path,
    query: null,
    headers: {
      [DEVICE_AUTHORIZATION_HEADER]: compactJws,
    },
    bodyBytes: null,
  })
}

async function sendSignedPost(args: {
  transport: DaaTransport
  operation: DeviceAuthorizationOperation
  path: string
  authKey: OwnerAuthKey
  authKeyId: string
  bodyBytes: Uint8Array
}): Promise<DaaHttpResponse> {
  const compactJws = await authorizeExactRequest({
    authKey: args.authKey,
    authKeyId: args.authKeyId,
    operation: args.operation,
    bodyBytes: args.bodyBytes,
  })
  return args.transport.send({
    method: 'POST',
    path: args.path,
    query: null,
    headers: {
      'Content-Type': 'application/json',
      [DEVICE_AUTHORIZATION_HEADER]: compactJws,
    },
    bodyBytes: args.bodyBytes,
  })
}

function mapSignedRequestFailure(response: DaaHttpResponse, bodyBytes: Uint8Array): DaaError {
  const correlationId = headerValueIgnoringCase(response.headers, 'X-Request-Id')
  const daaStatusCode = readDaaStatusCode(response.bodyBytes)
  const fallback = (): DaaError =>
    apiFailure({
      httpStatus: response.status,
      daaStatusCode,
      correlationId,
    })
  if (isDaaStatus(daaStatusCode, 'IDEMPOTENCY_KEY_REUSED')) {
    // Gated on both the status code and the HTTP status, so a body that
    // carries this code on some other status falls through to the generic
    // `api` failure below rather than being trusted. The contract puts this
    // code at `409`, which is where DAA's transfer and withdrawal
    // create routes send it. Non-custodial account create never sends it (a
    // reused key returns the original account). Recovered from the signed
    // request's own bytes, not the response — `idempotencyKeyFromExactBody`
    // returns `undefined` for a bodyless request (`getSignedResource`), so this
    // never fires for `get_device_context`.
    const idempotencyKey =
      response.status === 409 ? idempotencyKeyFromExactBody(bodyBytes) : undefined
    return idempotencyKey !== undefined
      ? idempotencyConflict(idempotencyKey, correlationId)
      : fallback()
  }
  if (
    isDaaStatus(daaStatusCode, 'DEVICE_AUTHORIZATION_REPLAYED') ||
    isDaaStatus(daaStatusCode, 'DEVICE_AUTHORIZATION_REQUEST_MISMATCH')
  ) {
    return contractViolation(
      'the device authorization was replayed or did not match the request',
      correlationId,
    )
  }
  if (isDaaStatus(daaStatusCode, 'DEVICE_AUTHORIZATION_INVALID')) {
    return contractViolation('the device authorization was rejected', correlationId)
  }
  return fallback()
}
