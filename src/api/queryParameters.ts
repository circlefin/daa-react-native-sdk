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

import { contractViolation } from '../errors'
import { isUuid } from '../validation/uuid'

export function append(parts: string[], name: string, value: string): void {
  try {
    parts.push(`${name}=${encodeURIComponent(value)}`)
  } catch {
    throw contractViolation(`${name} contains an invalid Unicode value`)
  }
}

export function appendString(parts: string[], name: string, value: string | undefined): void {
  if (value === undefined) return
  if (typeof value !== 'string' || value.length === 0) {
    throw contractViolation(`${name} must be a non-empty string`)
  }
  append(parts, name, value)
}

export function appendStrings(
  parts: string[],
  name: string,
  values: readonly string[] | undefined,
): void {
  if (values === undefined) return
  if (!Array.isArray(values)) {
    throw contractViolation(`${name} must be an array`)
  }
  for (const value of values) appendString(parts, name, value)
}

export function appendUuid(parts: string[], name: string, value: string | undefined): void {
  if (value === undefined) return
  if (typeof value !== 'string' || !isUuid(value)) {
    throw contractViolation(`${name} must be a UUID`)
  }
  append(parts, name, value)
}

export function appendEnum<const T extends string>(
  parts: string[],
  name: string,
  value: T | undefined,
  allowed: readonly T[],
): void {
  if (value === undefined) return
  if (typeof value !== 'string' || !allowed.includes(value)) {
    throw contractViolation(`${name} is not supported`)
  }
  append(parts, name, value)
}

export function appendEnums<const T extends string>(
  parts: string[],
  name: string,
  values: readonly T[] | undefined,
  allowed: readonly T[],
): void {
  if (values === undefined) return
  if (!Array.isArray(values)) {
    throw contractViolation(`${name} must be an array`)
  }
  for (const value of values) appendEnum(parts, name, value, allowed)
}
