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

// An account's limits and their current usage, as
// `GET /v1/accounts/{accountId}/limits/usage` reports it.
//
// The public API reference
// (https://developers.circle.com/api-reference/digital-asset-accounts/all/list-account-limits-usage)
// is this model's source of truth.
//
// Every closed-set field below follows the same discriminated-union-on-`kind`
// shape the rest of this SDK uses (`Account`'s four closed-set fields,
// `Deposit`'s status/type/rail): an unfamiliar *present* value degrades to
// `unrecognized` rather than failing the whole response, because a client
// cannot prove the service will never add a tenth `operation` or a third
// `window`.

/** The nine operations the public reference names for `operation`. */
export type LimitsUsageOperation =
  | { readonly kind: 'deposit' }
  | { readonly kind: 'withdrawal' }
  | { readonly kind: 'receive' }
  | { readonly kind: 'send' }
  | { readonly kind: 'send_count' }
  | { readonly kind: 'address_linking' }
  | { readonly kind: 'fiat_linking' }
  | { readonly kind: 'deposit_return_count' }
  | { readonly kind: 'balance_cap' }
  | { readonly kind: 'unrecognized'; readonly rawValue: string | null }

export type LimitsUsageAssetType =
  | { readonly kind: 'fiat' }
  | { readonly kind: 'crypto' }
  | { readonly kind: 'unrecognized'; readonly rawValue: string | null }

/**
 * Whether an item's `effectiveThreshold` is a per-transaction ceiling or a
 * rolling-window aggregate. Only an `aggregation` item carries `window`,
 * `currentAggregate`, or `usagePercent` — see `AccountLimitsUsageItem`.
 */
export type LimitsUsageComparisonType =
  | { readonly kind: 'transaction' }
  | { readonly kind: 'aggregation' }
  | { readonly kind: 'unrecognized'; readonly rawValue: string | null }

/** The unit `effectiveThreshold`/`currentAggregate` are denominated in. */
export type LimitsUsageUnit =
  | { readonly kind: 'usd_cents' }
  | { readonly kind: 'count' }
  | { readonly kind: 'unrecognized'; readonly rawValue: string | null }

/** The ISO 8601 rolling-window duration an `aggregation` item's threshold applies over. */
export type LimitsUsageWindow =
  | { readonly kind: 'PT24H' }
  | { readonly kind: 'P30D' }
  | { readonly kind: 'unrecognized'; readonly rawValue: string | null }

/**
 * The envelope's `type` discriminator. The public reference documents exactly
 * one value (`limitsUsage`); an unfamiliar one degrades to
 * `unrecognized` rather than failing the read, the same posture every other
 * closed-set field on this model takes.
 */
export type AccountLimitsUsageResourceType =
  | { readonly kind: 'limitsUsage' }
  | { readonly kind: 'unrecognized'; readonly rawValue: string | null }

/**
 * One limit/usage row for an `operation` x `assetType` pair.
 *
 * `window`, `currentAggregate`, and `usagePercent` are present **only** on a
 * `comparisonType: 'aggregation'` item; a `comparisonType: 'transaction'` item
 * typically omits all three, per the public reference's own example (a
 * transaction-limit row carries none of them). None of the three is required
 * on every item — requiring them would reject the transaction-limit rows the
 * service actually sends.
 *
 * `effectiveThreshold` and `currentAggregate` are the documented units
 * unconverted: a `usd_cents` value stays whole USD cents, and a `count` value
 * stays a whole-number count. Converting `usd_cents` to dollars here would
 * silently disagree with the wire value a caller can independently verify
 * against the public API response.
 */
export type AccountLimitsUsageItem = Readonly<{
  operation: LimitsUsageOperation
  assetType: LimitsUsageAssetType
  comparisonType: LimitsUsageComparisonType
  /** Present only for a rolling-window (`aggregation`) limit. */
  window: LimitsUsageWindow | null
  unit: LimitsUsageUnit
  /** Whole USD cents for `usd_cents`, a whole count for `count`. Never negative. */
  effectiveThreshold: number
  /** Present only for an `aggregation` limit. Same unit as `effectiveThreshold`. Never negative. */
  currentAggregate: number | null
  /** Present only for an `aggregation` limit. A percentage (0-100+), not a fraction. Never negative. */
  usagePercent: number | null
}>

/** The shape `JSON.stringify(accountLimitsUsage)` produces. Nothing here is redacted — see the class note. */
export type AccountLimitsUsageRendering = {
  readonly type: AccountLimitsUsageResourceType
  readonly accountId: string
  readonly currency: string
  readonly watermark: string
  readonly items: readonly AccountLimitsUsageItem[]
}

/**
 * An account's limits and current usage, as the SDK contract's
 * `AccountLimitsClient.get` result.
 *
 * **Not redacted.** Unlike `Money.amount`, `FiatAccount`'s `billingDetails`/
 * `bankAddress`, or a deposit's external references, nothing here falls under
 * the SDK's restricted-PII redaction rules or any comparable rule: these are
 * threshold/usage figures for the account's own limits, not a transaction
 * amount, a balance, or bank/PII detail. So every field is an ordinary own
 * property and the default `toJSON`/`toString` render all of them, the same
 * posture `Page` takes for its (non-sensitive) `items`.
 *
 * **Every field the public reference documents on `data` is guaranteed**
 * (`type`, `accountId`, `currency`, `watermark`, `items`); a response missing
 * one is a `contract_violation` rather than a value with holes in it, the same
 * rule every other model in this SDK applies.
 *
 * Not constructible by a consumer: exported from `index.ts` as a type only,
 * and the `#items` private field makes the type nominal.
 */
export class AccountLimitsUsage {
  readonly type: AccountLimitsUsageResourceType
  readonly accountId: string
  readonly currency: string
  /** "Freshness boundary for aggregate values" (public reference), as RFC 3339 text. */
  readonly watermark: string

  readonly #items: readonly AccountLimitsUsageItem[]

  /** @internal Constructed only by the SDK's response decoder. */
  constructor(fields: {
    readonly type: AccountLimitsUsageResourceType
    readonly accountId: string
    readonly currency: string
    readonly watermark: string
    readonly items: readonly AccountLimitsUsageItem[]
  }) {
    this.type = fields.type
    this.accountId = fields.accountId
    this.currency = fields.currency
    this.watermark = fields.watermark
    // Sliced before freezing, like `Account#balances`: freezing in place would
    // also freeze an array the caller (the wire mapper) still holds a
    // reference to.
    this.#items = Object.freeze(fields.items.slice())
    Object.freeze(this)
  }

  /** One row per `operation` x `assetType` pair the service reports. */
  get items(): readonly AccountLimitsUsageItem[] {
    return this.#items
  }

  toJSON(): AccountLimitsUsageRendering {
    return {
      type: this.type,
      accountId: this.accountId,
      currency: this.currency,
      watermark: this.watermark,
      items: this.#items,
    }
  }

  toString(): string {
    return (
      `AccountLimitsUsage(accountId=${this.accountId}, currency=${this.currency}, ` +
      `watermark=${this.watermark}, items=${this.#items.length} entries)`
    )
  }
}
