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

import { REDACTED } from './redaction'

// Shapes shared by the two fiat-account rails (`Wire`/`WireSummary` and `ACH`),
// per the canonical public Accounts OpenAPI's `WireSummary`/`Wire` schemas.
// `WireSummary`, `Wire`, `WireInstruction`, `ACH`, and `ACHInstruction` follow
// the canonical public Accounts OpenAPI's component naming, not DAA-owned
// aliases — but the status enum and the two nested address/billing shapes below
// are not themselves named by that public surface, so they follow this SDK's
// own naming convention for an unnamed nested shape (the same latitude
// `WithdrawalStatus` and `WithdrawalDestinationType` take in
// `models/Withdrawal.ts`).

/**
 * Lifecycle status of a fiat account, decoded from the service's
 * `ExternalFiatAccountStatus` wire enum (`pending` | `complete` | `failed`).
 *
 * Closed set for the same forward-compatibility reason as `DepositStatus`
 * (`models/Deposit.ts`): an unfamiliar *present* value degrades to
 * `unrecognized` rather than failing the whole response.
 */
export type FiatAccountStatus =
  | { readonly kind: 'pending' }
  | { readonly kind: 'complete' }
  | { readonly kind: 'failed' }
  | { readonly kind: 'unrecognized'; readonly rawValue: string | null }

/**
 * The fiat-account holder's billing address, as the service's `BillingDetails`
 * schema reports it (`name`, `city`, `country`, `line1`, `line2`, `district`,
 * `postalCode`, `valid`).
 *
 * Fiat-account `billingDetails`, `bankAddress`, and `routingNumber` must never
 * enter logs, traces, crash reports, or analytics. This follows
 * `BusinessPii`/`Address`'s pattern (`models/BusinessPii.ts`) rather than
 * `WithdrawalDetail`'s: every field is held behind a prototype accessor over a
 * `#` private field, so `Object.keys`, spread, `for...in`, and the inspectors
 * behind `console.log` see an empty object, and `toJSON`/`toString` render only
 * a redaction marker.
 */
export class BillingDetails {
  readonly #name: string
  readonly #city: string
  readonly #country: string
  readonly #line1: string
  readonly #line2: string | null
  readonly #district: string | null
  readonly #postalCode: string
  readonly #valid: boolean | null

  /** @internal Constructed only by the SDK's response decoder. */
  constructor(fields: {
    readonly name: string
    readonly city: string
    readonly country: string
    readonly line1: string
    readonly line2: string | null
    readonly district: string | null
    readonly postalCode: string
    readonly valid: boolean | null
  }) {
    this.#name = fields.name
    this.#city = fields.city
    this.#country = fields.country
    this.#line1 = fields.line1
    this.#line2 = fields.line2
    this.#district = fields.district
    this.#postalCode = fields.postalCode
    this.#valid = fields.valid
    Object.freeze(this)
  }

  get name(): string {
    return this.#name
  }

  get city(): string {
    return this.#city
  }

  get country(): string {
    return this.#country
  }

  get line1(): string {
    return this.#line1
  }

  get line2(): string | null {
    return this.#line2
  }

  get district(): string | null {
    return this.#district
  }

  get postalCode(): string {
    return this.#postalCode
  }

  get valid(): boolean | null {
    return this.#valid
  }

  toJSON(): string {
    return this.toString()
  }

  toString(): string {
    return `BillingDetails(${REDACTED})`
  }
}

/**
 * The receiving bank's address, as the service's `BankAddress` schema reports
 * it, and provided during bank-account creation.
 *
 * Redacted the same way {@link BillingDetails} is, and for the same reason:
 * `bankAddress` is restricted alongside `billingDetails` and `routingNumber`.
 */
export class BankAddress {
  readonly #bankName: string | null
  readonly #city: string | null
  readonly #country: string
  readonly #line1: string | null
  readonly #line2: string | null
  readonly #district: string | null

  /** @internal Constructed only by the SDK's response decoder. */
  constructor(fields: {
    readonly bankName: string | null
    readonly city: string | null
    readonly country: string
    readonly line1: string | null
    readonly line2: string | null
    readonly district: string | null
  }) {
    this.#bankName = fields.bankName
    this.#city = fields.city
    this.#country = fields.country
    this.#line1 = fields.line1
    this.#line2 = fields.line2
    this.#district = fields.district
    Object.freeze(this)
  }

  get bankName(): string | null {
    return this.#bankName
  }

  get city(): string | null {
    return this.#city
  }

  get country(): string {
    return this.#country
  }

  get line1(): string | null {
    return this.#line1
  }

  get line2(): string | null {
    return this.#line2
  }

  get district(): string | null {
    return this.#district
  }

  toJSON(): string {
    return this.toString()
  }

  toString(): string {
    return `BankAddress(${REDACTED})`
  }
}
