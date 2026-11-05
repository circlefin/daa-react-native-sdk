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

import { JSON_NUMBER } from './jsonNumber'

/**
 * The DAA status code from an error body, when the body carries a readable one.
 *
 * Best-effort by design: a failed call must still surface its HTTP status and
 * correlation id when the provider returned an empty body, a proxy's HTML error
 * page, or a shape the contract does not describe. Losing the whole error because
 * its detail did not parse would be worse than losing the detail, so every failure
 * here is `null`.
 *
 * Only the code is lifted. The envelope's `message` and `externalMessage` are
 * provider-authored text from a response the SDK cannot vouch for, and the SDK
 * error model has nowhere to put them that is not a log line.
 *
 * DAA sends the flat platform error body, with the code at the **root**:
 * `{"code":420034,"message":"…","externalMessage":"…"}`. The SDK also
 * accepts the code at `status.code`, but only when the root `code` is absent.
 * A root `code` that is present decides alone, even when it is unreadable or
 * unknown and `status.code` is a known code. Present means the key exists with
 * a value other than `null`. Neither is under `data`: the `data` success
 * wrapper is never applied to an error response.
 *
 * A decimal-string code comes back as the number. Any other string comes back
 * unchanged so that an `api` error can still show it, but it classifies
 * nothing: `isDaaStatus` matches numbers only.
 */
export function readDaaStatusCode(bytes: Uint8Array | null): string | number | null {
  if (bytes === null || bytes.length === 0) {
    return null
  }

  let root: unknown
  try {
    root = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown
  } catch {
    return null
  }

  if (!isObject(root)) {
    return null
  }
  const flat = root['code']
  if (flat !== undefined && flat !== null) {
    return codeValue(flat)
  }
  const status = root['status']
  return isObject(status) ? codeValue(status['code']) : null
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function codeValue(code: unknown): string | number | null {
  // A numeric code arrives as a number from `JSON.parse`. A status code is
  // small enough that no rounding question arises, so it is handed back as it
  // came.
  if (typeof code === 'number') {
    return Number.isFinite(code) ? code : null
  }
  if (typeof code !== 'string' || code.length === 0) {
    return null
  }
  // A code the service quoted is handed back as a number when it is one, so a
  // consumer can compare it without knowing which shape arrived. A string that
  // is not a number is kept only for diagnostics on the `api` error.
  return JSON_NUMBER.test(code) ? Number(code) : code
}
