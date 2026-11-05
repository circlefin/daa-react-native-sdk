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

import type { FiatAccountStatus } from '../models/FiatAccount'
import { BankAddress, BillingDetails } from '../models/FiatAccount'
import {
  MalformedPayloadError,
  asObject,
  optionalObject,
  optionalString,
  requiredString,
  unrecognized,
} from './payload'

/** Decoders shared by the wire and ACH fiat-account payloads (`wirePayload.ts`, `achPayload.ts`). */

const STATUSES = new Map<string, FiatAccountStatus>([
  ['pending', Object.freeze({ kind: 'pending' as const })],
  ['complete', Object.freeze({ kind: 'complete' as const })],
  ['failed', Object.freeze({ kind: 'failed' as const })],
])

export function toFiatAccountStatus(raw: string): FiatAccountStatus {
  return STATUSES.get(raw) ?? unrecognized(raw)
}

export function optionalBoolean(
  payload: Record<string, unknown>,
  name: string,
  label = name,
): boolean | null {
  const value = payload[name]
  if (value === undefined || value === null) {
    return null
  }
  if (typeof value !== 'boolean') {
    throw new MalformedPayloadError(label)
  }
  return value
}

/**
 * Decode the guaranteed `BillingDetails` shape.
 *
 * The service requires `name`, `city`, `country`, `line1`, and `postalCode` on
 * every wire/ACH fiat account, unlike `Account`'s optional `BusinessPii`
 * enrichment — so a fiat account missing one of these is a broken contract,
 * not a partially-enriched record.
 */
export function toBillingDetails(value: unknown, label: string): BillingDetails {
  const payload = asObject(value, label)
  return new BillingDetails({
    name: requiredString(payload, 'name', `${label}.name`),
    city: requiredString(payload, 'city', `${label}.city`),
    country: requiredString(payload, 'country', `${label}.country`),
    line1: requiredString(payload, 'line1', `${label}.line1`),
    line2: optionalString(payload, 'line2', `${label}.line2`),
    district: optionalString(payload, 'district', `${label}.district`),
    postalCode: requiredString(payload, 'postalCode', `${label}.postalCode`),
    valid: optionalBoolean(payload, 'valid', `${label}.valid`),
  })
}

export function requiredBillingDetails(
  payload: Record<string, unknown>,
  name: string,
): BillingDetails {
  const value = payload[name]
  if (value === undefined || value === null) {
    throw new MalformedPayloadError(name)
  }
  return toBillingDetails(value, name)
}

/**
 * Decode the optional `BankAddress` shape. Only `country` is guaranteed when
 * the object is present at all.
 */
export function toBankAddress(value: unknown, label: string): BankAddress {
  const payload = asObject(value, label)
  return new BankAddress({
    bankName: optionalString(payload, 'bankName', `${label}.bankName`),
    city: optionalString(payload, 'city', `${label}.city`),
    country: requiredString(payload, 'country', `${label}.country`),
    line1: optionalString(payload, 'line1', `${label}.line1`),
    line2: optionalString(payload, 'line2', `${label}.line2`),
    district: optionalString(payload, 'district', `${label}.district`),
  })
}

export function optionalBankAddress(
  payload: Record<string, unknown>,
  name: string,
): BankAddress | null {
  const value = optionalObject(payload, name)
  return value === null ? null : toBankAddress(value, name)
}
