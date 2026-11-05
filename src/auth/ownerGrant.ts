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

// Owner-grant claim check. The public Social Session contract does
// not return an Owner grant — Circle keeps that assertion internal. If a
// response nevertheless carries one, the SDK must not invent a grant shape and
// must not proceed without the flow-key binding Complete's dual headers rely on.
//
// Cryptographic verification of a grant is not done here. This
// only reads the compact-JWT payload and requires
// `registrationFlowKeyThumbprint`. The grant is never logged, stored, or
// forwarded to Device Registration Complete.

import { fromBase64Url } from '../crypto/base64url'
import { contractViolation } from '../errors'

/** RFC 7638 P-256 `jkt` is an unpadded Base64URL SHA-256 digest: 43 characters. */
const JWK_THUMBPRINT = /^[A-Za-z0-9_-]{43}$/

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/**
 * Require a compact Owner grant to carry `registrationFlowKeyThumbprint`.
 *
 * `correlationId` is the `X-Request-Id` of the response that carried the grant,
 * so the failure can be traced server-side like any other error built from a
 * response.
 *
 * @throws DaaError `contract_violation` when the grant is missing, unreadable,
 *   missing the thumbprint, or bound to a different flow key. The grant itself
 *   is never interpolated into the error.
 */
export function requireOwnerGrantFlowKeyThumbprint(
  ownerGrant: string,
  expectedThumbprint: string,
  correlationId: string | null,
): void {
  const claims = compactJwtPayload(ownerGrant, correlationId)
  const thumbprint = claims.registrationFlowKeyThumbprint
  if (typeof thumbprint !== 'string' || !JWK_THUMBPRINT.test(thumbprint)) {
    throw contractViolation('owner grant is missing registrationFlowKeyThumbprint', correlationId)
  }
  if (thumbprint !== expectedThumbprint) {
    throw contractViolation(
      'owner grant registrationFlowKeyThumbprint does not match the registration-flow key',
      correlationId,
    )
  }
}

function compactJwtPayload(compact: string, correlationId: string | null): Record<string, unknown> {
  const parts = compact.split('.')
  const header = parts[0]
  const payload = parts[1]
  const signature = parts[2]
  if (
    parts.length !== 3 ||
    header === undefined ||
    payload === undefined ||
    signature === undefined ||
    header.length === 0 ||
    payload.length === 0 ||
    signature.length === 0
  ) {
    throw contractViolation('owner grant must be a compact JWT', correlationId)
  }

  let bytes: Uint8Array
  try {
    bytes = fromBase64Url(payload)
  } catch {
    throw contractViolation('owner grant payload is not valid Base64URL', correlationId)
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
  } catch {
    throw contractViolation('owner grant payload is not JSON', correlationId)
  }
  if (!isJsonObject(parsed)) {
    throw contractViolation('owner grant payload is not a JSON object', correlationId)
  }
  return parsed
}
