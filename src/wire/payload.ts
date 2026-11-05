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
 * Raised when a response is missing something the service guarantees, or carries
 * it in a shape the contract does not describe.
 *
 * Internal, and caught at the client boundary where it becomes the one
 * `contract_violation` carrying the correlation id. `fieldName` exists so a
 * decoder test can say which field it rejected; it is deliberately **not**
 * propagated into the error a consumer sees, because it names a field in a
 * response the SDK cannot vouch for.
 */
export class MalformedPayloadError extends Error {
  readonly fieldName: string

  constructor(fieldName: string) {
    super(`DAA: response field is missing or not the expected shape: ${fieldName}`)
    this.name = 'MalformedPayloadError'
    this.fieldName = fieldName
  }
}

/** Preserve an unfamiliar closed-set wire value without failing its resource. */
export function unrecognized(rawValue: string | null): {
  readonly kind: 'unrecognized'
  readonly rawValue: string | null
} {
  return Object.freeze({ kind: 'unrecognized' as const, rawValue })
}

export function asObject(value: unknown, field: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new MalformedPayloadError(field)
  }
  return value as Record<string, unknown>
}

/** An object field the service may omit. JSON `null` is treated as absence. */
export function optionalObject(
  payload: Record<string, unknown>,
  name: string,
): Record<string, unknown> | null {
  const value = payload[name]
  if (value === undefined || value === null) {
    return null
  }
  return asObject(value, name)
}

/** A field the service may omit. JSON `null` is treated as absence. */
export function optionalString(
  payload: Record<string, unknown>,
  name: string,
  label = name,
): string | null {
  const value = payload[name]
  if (value === undefined || value === null) {
    return null
  }
  if (typeof value !== 'string') {
    throw new MalformedPayloadError(label)
  }
  return value
}

/** A field the service guarantees. Absent, null, or not a string is malformed. */
export function requiredString(
  payload: Record<string, unknown>,
  name: string,
  label = name,
): string {
  const value = optionalString(payload, name, label)
  if (value === null) {
    throw new MalformedPayloadError(label)
  }
  return value
}

/**
 * A non-negative integer field the service guarantees, sent as a JSON number
 * rather than a string.
 *
 * Unlike `Money.amount` (a decimal serialized as a string to survive
 * `JSON.parse` exactly), an int64 count or a `usd_cents` threshold is sent as
 * an ordinary JSON number, so there is no second encoding to unwrap here — only
 * the grammar (integer, non-negative) to check.
 */
export function requiredNonNegativeInteger(
  payload: Record<string, unknown>,
  name: string,
  label = name,
): number {
  const value = payload[name]
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
    throw new MalformedPayloadError(label)
  }
  return value
}

/** A non-negative integer field the service may omit. JSON `null` is treated as absence. */
export function optionalNonNegativeInteger(
  payload: Record<string, unknown>,
  name: string,
  label = name,
): number | null {
  const value = payload[name]
  if (value === undefined || value === null) {
    return null
  }
  return requiredNonNegativeInteger(payload, name, label)
}

/**
 * A non-negative decimal field the service may omit (for example a usage
 * percentage), sent as a JSON number. JSON `null` is treated as absence.
 */
export function optionalNonNegativeNumber(
  payload: Record<string, unknown>,
  name: string,
  label = name,
): number | null {
  const value = payload[name]
  if (value === undefined || value === null) {
    return null
  }
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    throw new MalformedPayloadError(label)
  }
  return value
}
