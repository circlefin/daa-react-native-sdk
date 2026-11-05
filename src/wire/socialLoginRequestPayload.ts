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

import { isUuid } from '../validation/uuid'
import { requiredDateTime } from './instant'
import { asObject, MalformedPayloadError, requiredString } from './payload'

// Decoder for Prepare's `201` `data` payload.
//
// The `PreparedSocialLogin` body is loginRequestId, oidcNonce, oidcState,
// expiresAt, and `prepareReceiptJws` when the service signs a receipt. Extra
// response members are ignored.
//
// The receipt is carried through raw and not examined here: not its presence,
// its type, or its shape. What to do with it is decided per environment by
// `auth/prepareReceipt.ts`'s `checkPrepareReceipt`, which `prepareSocialLogin`
// calls right after this decoder. With no trust anchor pinned the receipt is
// ignored, so a receipt the SDK cannot use must not fail the response here;
// with an anchor pinned, a missing or malformed receipt is
// `prepare_receipt_invalid` there rather than a malformed response here.

const OIDC_VALUE_MIN = 32
const OIDC_VALUE_MAX = 256

export type SocialLoginRequestPayload = Readonly<{
  loginRequestId: string
  oidcNonce: string
  oidcState: string
  /** ISO-8601, normalised when the service sends epoch milliseconds instead. */
  expiresAt: string
  /**
   * The raw `prepareReceiptJws` member, unvalidated: `null` when absent. Only
   * `checkPrepareReceipt` reads it.
   */
  prepareReceiptJws: unknown
}>

function requiredUuid(payload: Record<string, unknown>, name: string): string {
  const value = requiredString(payload, name)
  if (!isUuid(value)) {
    throw new MalformedPayloadError(name)
  }
  return value
}

function requiredOidcValue(payload: Record<string, unknown>, name: string): string {
  const value = requiredString(payload, name)
  if (value.length < OIDC_VALUE_MIN || value.length > OIDC_VALUE_MAX) {
    throw new MalformedPayloadError(name)
  }
  return value
}

/** The raw receipt member: `null` when absent or JSON `null`, else whatever was sent. */
function rawPrepareReceipt(payload: Record<string, unknown>): unknown {
  const value = Object.prototype.hasOwnProperty.call(payload, 'prepareReceiptJws')
    ? payload['prepareReceiptJws']
    : undefined
  return value === undefined ? null : value
}

/** Map a Prepare success payload onto the fields the SDK keeps. */
export function toSocialLoginRequest(value: unknown): SocialLoginRequestPayload {
  const payload = asObject(value, 'payload')
  return {
    loginRequestId: requiredUuid(payload, 'loginRequestId'),
    oidcNonce: requiredOidcValue(payload, 'oidcNonce'),
    oidcState: requiredOidcValue(payload, 'oidcState'),
    // The service sends this as epoch milliseconds; the decoder also accepts
    // ISO-8601. See `instant.ts`.
    expiresAt: requiredDateTime(payload, 'expiresAt'),
    prepareReceiptJws: rawPrepareReceipt(payload),
  }
}
