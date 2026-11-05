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

import { MalformedPayloadError, requiredString } from './payload'

// The two wire forms a login-flow timestamp arrives in, and the single form
// the login decoders hand on.
//
// By default the service serialises a timestamp as a JSON number: an integral
// count of epoch milliseconds, not fractional seconds. Most timestamps opt out
// and are sent as ISO-8601 strings: every response carrying a `createDate` /
// `updateDate` does. Exactly three responses do not — Prepare
// (`PreparedSocialLogin`), Session and the device context — and those three are
// the login flow's three responses. The number form is therefore not a
// service-wide habit but a property of precisely the fields these decoders
// read, which is why this lives on its own rather than in `payload.ts` beside
// `requiredString`: a resource `createDate` arriving as a number would be a real
// contract violation, and `deposit`/`transfer`/`withdrawal` must keep rejecting
// it.
//
// The three fields are `PreparedSocialLogin.expiresAt`,
// `SocialSession.expiresAt` and `DeviceContext.resolvedAt`. They are the same
// kind of field, serialised the same way, so all three accept both forms.

/**
 * The ISO-8601 form the contract declares for an `Instant`, with a `T`
 * separator. The service does not always send this form — see `requiredDateTime`
 * — but it is the single form these decoders hand on.
 */
const DATE_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/

/**
 * Render epoch milliseconds as the same ISO-8601 text the string form carries.
 *
 * Three checks, no coercions. A fractional, non-finite, or beyond-safe-integer
 * value is not a count of milliseconds, and zero or below is a field that
 * arrived as a number without being a timestamp. What survives that can still be
 * outside the range `Date` represents, so the instant is checked before it is
 * rendered. The rendered text then has to satisfy `DATE_TIME` exactly as the
 * string form does — which is what bounds the year, rather than an invented
 * constant: an epoch rendering `'+275760-09-13T00:00:00.000Z'` is rejected here
 * for the same reason that string would be.
 */
function fromEpochMillis(value: number, name: string): string {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new MalformedPayloadError(name)
  }
  const instant = new Date(value)
  if (Number.isNaN(instant.getTime())) {
    throw new MalformedPayloadError(name)
  }
  const text = instant.toISOString()
  if (!DATE_TIME.test(text)) {
    throw new MalformedPayloadError(name)
  }
  return text
}

/**
 * A login-flow timestamp the service guarantees, in either form it sends.
 *
 * The contract OpenAPI declares an ISO-8601 string and the running service
 * sends a JSON number of epoch milliseconds, so the SDK accepts both. A number
 * is normalised to the string form at this boundary, so every public timestamp
 * stays one stable type no matter which form arrived. Anything that is neither
 * form still fails closed.
 */
export function requiredDateTime(payload: Record<string, unknown>, name: string): string {
  const raw = payload[name]
  if (typeof raw === 'number') {
    return fromEpochMillis(raw, name)
  }
  const value = requiredString(payload, name)
  if (!DATE_TIME.test(value)) {
    throw new MalformedPayloadError(name)
  }
  return value
}
