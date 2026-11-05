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

/**
 * The DAA status codes this SDK classifies, keyed by a symbolic name for each
 * row. The names are labels for this code. DAA never sends them: it sends only
 * the numeric code, and {@link isDaaStatus} matches only that number. This
 * table is the one place a number appears; every mapping goes through {@link
 * isDaaStatus}.
 *
 * Only rows with a numeric code are here. Some conditions have no distinct DAA
 * code, such as `DEVICE_AUTHORIZATION_EXPIRED`,
 * `DEVICE_AUTHORIZATION_MISSING` and `DEVICE_CREDENTIAL_REVOKED`. DAA reports
 * those with another code, and the SDK must not infer the condition from it.
 * A non-numeric string `code` matches nothing and classifies as `api`, whether
 * it is the name of a row in this table, the name of a condition with no code,
 * or a name that is not a DAA status code at all, such as
 * `OWNER_AUTHORIZATION_INVALID`.
 *
 * The signed-request mapping (`api/signedResource.ts`) matches
 * `DEVICE_AUTHORIZATION_INVALID`, `IDEMPOTENCY_KEY_REUSED`,
 * `DEVICE_AUTHORIZATION_REQUEST_MISMATCH` and `DEVICE_AUTHORIZATION_REPLAYED`.
 * The login mapping (`api/loginFailure.ts`) matches `IDEMPOTENCY_KEY_REUSED`
 * and `LOGIN_REQUEST_CONSUMED`. The unsigned deposit-address create
 * (`api/DepositAddressesClient.ts`) matches `IDEMPOTENCY_KEY_REUSED`.
 * `AUTH_KEY_BINDING_CONFLICT` is in the table because DAA returns it with `409`
 * from Device Registration Complete. It classifies as `api`, so no mapping
 * matches it, and the login mapping does not let its `409` become
 * `idempotency_conflict`. The numbers are stable: DAA retires a code rather than
 * reusing it.
 */
export const DAA_STATUS_CODES = Object.freeze({
  DEVICE_AUTHORIZATION_INVALID: 420031,
  IDEMPOTENCY_KEY_REUSED: 420034,
  DEVICE_AUTHORIZATION_REQUEST_MISMATCH: 420036,
  AUTH_KEY_BINDING_CONFLICT: 420038,
  LOGIN_REQUEST_CONSUMED: 420039,
  DEVICE_AUTHORIZATION_REPLAYED: 420043,
} as const satisfies Readonly<Record<string, number>>)

export type DaaStatusName = keyof typeof DAA_STATUS_CODES

/**
 * Whether a code read by `readDaaStatusCode` is the named DAA status.
 *
 * The matching rule: a DAA error is classified on its numeric code only.
 * `name` selects the row; the code matches only when it is that row's number.
 * A decimal string such as `"420034"` already arrives here as the number. Any
 * other string, including the row's own name, is not a match, so it falls
 * through to `api`. `null` (no readable code) is not a match either.
 */
export function isDaaStatus(code: string | number | null, name: DaaStatusName): boolean {
  return typeof code === 'number' && code === DAA_STATUS_CODES[name]
}
