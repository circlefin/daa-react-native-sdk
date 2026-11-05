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

// Deterministic, exact-byte body serialization.
//
// The SDK serializes a request body exactly once and then signs and sends that
// same immutable byte slice. It never canonicalizes or re-serializes the body.
// Callers must treat the returned Uint8Array as immutable.

/**
 * Serialize a JSON request body to its exact UTF-8 bytes, once.
 *
 * @throws if the value cannot be represented as JSON (e.g. contains only
 *   `undefined`, a function, or a BigInt).
 */
export function serializeBody(value: unknown): Uint8Array {
  const json = JSON.stringify(value)
  if (json === undefined) {
    throw new Error('DAA: request body is not JSON-serializable')
  }
  return new TextEncoder().encode(json)
}

/** The exact-byte representation of a body-less request: the empty byte array. */
export function serializeEmptyBody(): Uint8Array {
  return new Uint8Array(0)
}
