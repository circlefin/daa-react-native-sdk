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

// Local checks on a request body before it is serialized, signed, and sent.
//
// These exist because the Owner-authorization registry declares every signed
// operation's schema `additionalProperties: false`, and DAA enforces it
// property by property. A body carrying a property the schema does not name is
// refused there, so the SDK refuses it here — where the caller still has the
// stack that produced it, and before an Owner signature has been spent on bytes
// that cannot succeed.
//
// Rejecting is deliberate, and it is not the same as projecting the known
// properties and dropping the rest. A dropped property is a silent change of
// meaning: `blockChain` for `blockchain` would create an account on the default
// home chain rather than the requested one, and the caller would have no way to
// tell from the result that the field it set was never sent.

import { contractViolation } from '../errors'

/** Refuse anything that is not a plain JSON object, including an array or null. */
export function requireBodyObject(value: unknown, label: string): void {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw contractViolation(`${label} must be an object`)
  }
}

/**
 * Refuse a property the operation's registry schema does not name.
 *
 * `Object.keys` reports own enumerable string keys, which is exactly the set
 * `JSON.stringify` would serialize — so this checks the properties that would
 * actually reach the wire rather than a structural approximation of them.
 */
export function requireKnownProperties(
  value: object,
  allowed: readonly string[],
  label: string,
): void {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) {
      throw contractViolation(`${label} does not accept the property "${key}"`)
    }
  }
}
