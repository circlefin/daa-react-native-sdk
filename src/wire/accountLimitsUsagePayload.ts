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

import type {
  AccountLimitsUsageItem,
  AccountLimitsUsageResourceType,
  LimitsUsageAssetType,
  LimitsUsageComparisonType,
  LimitsUsageOperation,
  LimitsUsageUnit,
  LimitsUsageWindow,
} from '../models/AccountLimitsUsage'
import { AccountLimitsUsage } from '../models/AccountLimitsUsage'
import {
  asObject,
  MalformedPayloadError,
  optionalNonNegativeInteger,
  optionalNonNegativeNumber,
  optionalString,
  requiredNonNegativeInteger,
  requiredString,
  unrecognized,
} from './payload'

// Wire-string to public-type mapping, one `Map` per closed-set field — the
// same `Object.prototype` hazard `wireEnums.ts` guards against, kept local to
// this endpoint the same way `depositPayload.ts` keeps `DEPOSIT_STATUSES` and
// `DEPOSIT_TYPES` local rather than exporting them off the model.

const RESOURCE_TYPES = new Map<string, AccountLimitsUsageResourceType>([
  ['limitsUsage', Object.freeze({ kind: 'limitsUsage' as const })],
])

const OPERATIONS = new Map<string, LimitsUsageOperation>([
  ['deposit', Object.freeze({ kind: 'deposit' as const })],
  ['withdrawal', Object.freeze({ kind: 'withdrawal' as const })],
  ['receive', Object.freeze({ kind: 'receive' as const })],
  ['send', Object.freeze({ kind: 'send' as const })],
  ['send_count', Object.freeze({ kind: 'send_count' as const })],
  ['address_linking', Object.freeze({ kind: 'address_linking' as const })],
  ['fiat_linking', Object.freeze({ kind: 'fiat_linking' as const })],
  ['deposit_return_count', Object.freeze({ kind: 'deposit_return_count' as const })],
  ['balance_cap', Object.freeze({ kind: 'balance_cap' as const })],
])

const ASSET_TYPES = new Map<string, LimitsUsageAssetType>([
  ['fiat', Object.freeze({ kind: 'fiat' as const })],
  ['crypto', Object.freeze({ kind: 'crypto' as const })],
])

const COMPARISON_TYPES = new Map<string, LimitsUsageComparisonType>([
  ['transaction', Object.freeze({ kind: 'transaction' as const })],
  ['aggregation', Object.freeze({ kind: 'aggregation' as const })],
])

const UNITS = new Map<string, LimitsUsageUnit>([
  ['usd_cents', Object.freeze({ kind: 'usd_cents' as const })],
  ['count', Object.freeze({ kind: 'count' as const })],
])

const WINDOWS = new Map<string, LimitsUsageWindow>([
  ['PT24H', Object.freeze({ kind: 'PT24H' as const })],
  ['P30D', Object.freeze({ kind: 'P30D' as const })],
])

function toResourceType(raw: string): AccountLimitsUsageResourceType {
  return RESOURCE_TYPES.get(raw) ?? unrecognized(raw)
}

function toOperation(raw: string): LimitsUsageOperation {
  return OPERATIONS.get(raw) ?? unrecognized(raw)
}

function toAssetType(raw: string): LimitsUsageAssetType {
  return ASSET_TYPES.get(raw) ?? unrecognized(raw)
}

function toComparisonType(raw: string): LimitsUsageComparisonType {
  return COMPARISON_TYPES.get(raw) ?? unrecognized(raw)
}

function toUnit(raw: string): LimitsUsageUnit {
  return UNITS.get(raw) ?? unrecognized(raw)
}

function toWindow(raw: string): LimitsUsageWindow {
  return WINDOWS.get(raw) ?? unrecognized(raw)
}

/**
 * Map one decoded `items[]` element onto the public shape.
 *
 * `window`, `currentAggregate`, and `usagePercent` are read as optional
 * unconditionally — there is no `comparisonType` branch that requires them.
 * The public reference's own example shows a `transaction` item omitting all
 * three and an `aggregation` item carrying all three, but nothing here
 * enforces that correlation: a service that sent an `aggregation` item
 * without, say, `usagePercent` would still decode rather than fail the whole
 * read, which is the same latitude this SDK gives every other
 * service-guarantees-in-practice-but-not-by-schema field (see `Deposit`'s
 * class note on `destination`).
 *
 * @throws MalformedPayloadError
 */
function toAccountLimitsUsageItem(value: unknown): AccountLimitsUsageItem {
  const payload = asObject(value, 'accountLimitsUsage.items[]')

  const window = optionalString(payload, 'window')
  return Object.freeze({
    operation: toOperation(
      requiredString(payload, 'operation', 'accountLimitsUsage.items[].operation'),
    ),
    assetType: toAssetType(
      requiredString(payload, 'assetType', 'accountLimitsUsage.items[].assetType'),
    ),
    comparisonType: toComparisonType(
      requiredString(payload, 'comparisonType', 'accountLimitsUsage.items[].comparisonType'),
    ),
    window: window === null ? null : toWindow(window),
    unit: toUnit(requiredString(payload, 'unit', 'accountLimitsUsage.items[].unit')),
    effectiveThreshold: requiredNonNegativeInteger(
      payload,
      'effectiveThreshold',
      'accountLimitsUsage.items[].effectiveThreshold',
    ),
    currentAggregate: optionalNonNegativeInteger(
      payload,
      'currentAggregate',
      'accountLimitsUsage.items[].currentAggregate',
    ),
    usagePercent: optionalNonNegativeNumber(
      payload,
      'usagePercent',
      'accountLimitsUsage.items[].usagePercent',
    ),
  })
}

function toAccountLimitsUsageItems(value: unknown): readonly AccountLimitsUsageItem[] {
  if (!Array.isArray(value)) {
    throw new MalformedPayloadError('accountLimitsUsage.items')
  }
  return Object.freeze(value.map(toAccountLimitsUsageItem))
}

/**
 * Map a decoded `GET /v1/accounts/{accountId}/limits/usage` payload onto the
 * public model.
 *
 * `type`, `accountId`, `currency`, `watermark`, and `items` are all required —
 * the public reference marks every one of them required on `data`, and this is
 * a single-object envelope (see `AccountLimitsClient.get`), not a page, so
 * there is no separate list-projection type the way `deposits.list` has one.
 *
 * @throws MalformedPayloadError
 */
export function toAccountLimitsUsage(value: unknown): AccountLimitsUsage {
  const payload = asObject(value, 'accountLimitsUsage')

  return new AccountLimitsUsage({
    type: toResourceType(requiredString(payload, 'type', 'accountLimitsUsage.type')),
    accountId: requiredString(payload, 'accountId'),
    currency: requiredString(payload, 'currency'),
    watermark: requiredString(payload, 'watermark'),
    items: toAccountLimitsUsageItems(payload['items']),
  })
}
