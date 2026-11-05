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

import { Money } from '../models/Money'
import { JSON_NUMBER } from './jsonNumber'
import { asObject, MalformedPayloadError, requiredString } from './payload'

/**
 * Decode the shared `Money` wire shape without coercing its decimal.
 *
 * The service serializes `amount` as a plain decimal JSON string. Accepting a JSON number would lose precision in
 * `JSON.parse` before this decoder could inspect it, so only an RFC 8259
 * number-shaped string is accepted. `Money` owns redaction of the amount.
 */
export function toMoney(value: unknown, label: string): Money {
  const payload = asObject(value, label)
  const amount = requiredString(payload, 'amount', `${label}.amount`)
  if (!JSON_NUMBER.test(amount)) {
    throw new MalformedPayloadError(`${label}.amount`)
  }
  return new Money(amount, requiredString(payload, 'currency', `${label}.currency`))
}

/** Decode a guaranteed money field. */
export function requiredMoney(payload: Record<string, unknown>, name: string): Money {
  const value = payload[name]
  if (value === undefined || value === null) {
    throw new MalformedPayloadError(name)
  }
  return toMoney(value, name)
}

/** Decode a money field the service may omit. JSON `null` is absence. */
export function optionalMoney(payload: Record<string, unknown>, name: string): Money | null {
  const value = payload[name]
  if (value === undefined || value === null) {
    return null
  }
  return toMoney(value, name)
}
