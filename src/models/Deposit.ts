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

import type { Money } from './Money'

// The closed-set fields on a deposit, and the two location shapes it carries.
//
// Each is a discriminated union on `kind`, the same shape `Account`'s closed-set
// fields use (see `models/Account.ts`) and for the same reason: a string-literal
// union has no room for a value the service adds next, and decoding into one
// would either throw (this SDK could no longer read *any* deposit because one
// status was added service-side) or silently widen to `string`, discarding the
// closed set the type exists to express. An unfamiliar *present* value degrades
// to `unrecognized` **carrying the raw string**, per the SDK contract's
// requirement to preserve it "as an unknown/raw-value case instead of failing
// the entire response".

/**
 * Public lifecycle status of a DAA account deposit.
 *
 * The service's `DepositStatus` enum has exactly three wire values — `pending`,
 * `complete`, `failed` — and owns the two-way translation from the finer
 * payment-processor status. Modelled as a closed set for the same
 * forward-compatibility reason as `AccountStatus`.
 */
export type DepositStatus =
  | { readonly kind: 'pending' }
  | { readonly kind: 'complete' }
  | { readonly kind: 'failed' }
  | { readonly kind: 'unrecognized'; readonly rawValue: string | null }

/**
 * The fiat rail a deposit's source account was received over.
 *
 * The service's `DepositType` enum lists fourteen wire values, all already
 * lower_snake_case, so (unlike `AccountType`'s `first_party`/`firstParty` split)
 * a `kind` here is spelled identically to its own wire value. New rails ship
 * before an SDK release picks them up, which is exactly the case `unrecognized`
 * exists for.
 */
export type DepositType =
  | { readonly kind: 'wire' }
  | { readonly kind: 'ach' }
  | { readonly kind: 'cbit' }
  | { readonly kind: 'rtgs' }
  | { readonly kind: 'rtp' }
  | { readonly kind: 'xpay' }
  | { readonly kind: 'signet' }
  | { readonly kind: 'sepa' }
  | { readonly kind: 'sepa_instant' }
  | { readonly kind: 'sen' }
  | { readonly kind: 'pix' }
  | { readonly kind: 'cubix' }
  | { readonly kind: 'book_transfer' }
  | { readonly kind: 'fed_now' }
  | { readonly kind: 'unrecognized'; readonly rawValue: string | null }

/**
 * The DAA account a deposit was credited to.
 *
 * The service's `DepositAccountLocation` has one `type` constant (`account`),
 * but that is not a wire guarantee, and `type` is serialized as an ordinary
 * string discriminator on the same location family the transfer and withdrawal
 * models use for on-chain legs.
 * Modelled as a closed set rather than a fixed `{ kind: 'account' }` so a future
 * non-account destination degrades instead of failing the read.
 */
export type DepositAccountLocation =
  | { readonly kind: 'account'; readonly accountId: string }
  | { readonly kind: 'unrecognized'; readonly rawValue: string | null }

/**
 * The originating fiat account a deposit was received from, when the service
 * can identify it.
 *
 * `type` and `id` are guaranteed together: the service returns a source
 * location only when both are present and `type` parses, so a decoded source
 * location never has one without the other. `name` is a best-effort
 * display label and is not guaranteed even when the rest is.
 */
export type DepositSourceLocation = {
  readonly type: DepositType
  readonly id: string
  readonly name: string | null
}

/**
 * A risk evaluation on a deposit.
 *
 * Both fields are free-form upstream strings the service does not itself
 * constrain to a closed set — the schema's `allowableValues` on `decision`
 * documents examples, not a contract — so neither is modelled as one here. The
 * service surfaces the object whenever either field exists, so a reason-only
 * evaluation has a `null` decision.
 */
export type DepositRiskEvaluation = {
  readonly decision: string | null
  readonly reason: string | null
}

/** The redacted shape `JSON.stringify(deposit)` produces. Every amount is a `Money`, which self-redacts. */
export type DepositRendering = {
  readonly amount: Money
  readonly createDate: string
  readonly destination: DepositAccountLocation | null
  readonly fee: Money | null
  readonly fees: Money | null
  readonly fromAmount: Money | null
  readonly id: string
  readonly status: DepositStatus
}

/**
 * A DAA account deposit, as the service reports it.
 *
 * Read-only at runtime as well as in the type system, for the same reason as
 * `Account`: the instance is frozen, because `readonly` is erased at compile
 * time and would leave a returned deposit mutable through a cast.
 *
 * **Not constructible by a consumer.** Exported from `index.ts` as a **type
 * only**, so no runtime constructor reaches the public entry, and
 * the `#` private fields make the type nominal so an object literal cannot be
 * typed as a `Deposit` either. Every instance a caller holds came from a
 * response this SDK decoded.
 *
 * **The guaranteed set does not follow the OpenAPI schema's required
 * marking,** which covers only a few fields here and which this SDK already
 * treats as non-authoritative for `Account` (see `wire/accountPayload.ts`). The
 * guaranteed set here is read from what the service can actually produce
 * across both the omnibus and segregated read paths:
 *
 * - `id`, `amount`, `status`, and `createDate` have no code path that leaves
 *   them absent on either source, so they are guaranteed here.
 * - `destination` is marked required, but the service reports `null` whenever
 *   the ledger leg the deposit landed on is not a wallet location — a real code
 *   path, not a hypothetical one — so this SDK treats it as optional despite
 *   the schema. Trusting the schema would be the same defect documented for
 *   `Account.description`.
 * - `updateDate` is **not** marked required at all, even though both read
 *   paths suggest it is in practice always present. It is still
 *   modelled optional: the risk is asymmetric, because a wrongly-required field
 *   rejects a valid response outright while a wrongly-optional field only
 *   under-promises a type. Absent a marker to settle it, the safer side wins.
 *
 * Everything else the service can omit is optional here.
 *
 * **Sensitive fields do not appear in any default rendering.** `amount`, `fee`,
 * `fees`, `fromAmount`, `externalRef`, and `customerExternalRef` sit behind
 * prototype accessors over `#` private fields, following `Money` and
 * `BusinessPii`: `Object.keys`, `JSON.stringify`, spread, `for...in`, and the
 * inspectors behind `console.log` cannot reach the fields themselves. Each
 * `Money` additionally withholds its own amount text. The external references
 * are bank/customer-supplied values that the service also redacts from metadata
 * logging. Service-assigned identifiers, states, and locations remain visible so
 * a log line naming a deposit by id and status stays useful.
 */
export class Deposit {
  readonly createDate: string

  /**
   * The account credited by the deposit, when the service can attribute one.
   * `null` when the ledger leg the deposit landed on is not a wallet — see the
   * class note.
   */
  readonly destination: DepositAccountLocation | null

  /** Failure reason. Present only for a `failed` deposit. A free-form upstream code, not a closed set. */
  readonly errorCode: string | null

  /** Service-assigned identifier. */
  readonly id: string

  /** Risk evaluation; present whenever the service reports either risk field. */
  readonly riskEvaluation: DepositRiskEvaluation | null

  /** The originating fiat account, when the service can identify it. */
  readonly source: DepositSourceLocation | null

  /** Originating fiat account id the deposit was received from. */
  readonly sourceAccountId: string | null

  readonly status: DepositStatus

  /** Tracking reference. */
  readonly trackingRef: string | null

  /**
   * Last-update timestamp (ISO-8601 UTC), as the service sent it. Carried as the
   * exact wire string rather than parsed into a `Date` — this SDK does not
   * introduce a second representation of a value it does not compute over.
   * `null` only out of caution; see the class note.
   */
  readonly updateDate: string | null

  readonly #amount: Money
  readonly #customerExternalRef: string | null
  readonly #externalRef: string | null
  readonly #fee: Money | null
  readonly #fees: Money | null
  readonly #fromAmount: Money | null

  /** @internal Constructed only by the SDK's response decoder. */
  constructor(fields: {
    readonly amount: Money
    readonly createDate: string
    readonly customerExternalRef: string | null
    readonly destination: DepositAccountLocation | null
    readonly errorCode: string | null
    readonly externalRef: string | null
    readonly fee: Money | null
    readonly fees: Money | null
    readonly fromAmount: Money | null
    readonly id: string
    readonly riskEvaluation: DepositRiskEvaluation | null
    readonly source: DepositSourceLocation | null
    readonly sourceAccountId: string | null
    readonly status: DepositStatus
    readonly trackingRef: string | null
    readonly updateDate: string | null
  }) {
    this.createDate = fields.createDate
    this.destination = fields.destination
    this.errorCode = fields.errorCode
    this.id = fields.id
    this.riskEvaluation = fields.riskEvaluation
    this.source = fields.source
    this.sourceAccountId = fields.sourceAccountId
    this.status = fields.status
    this.trackingRef = fields.trackingRef
    this.updateDate = fields.updateDate
    this.#amount = fields.amount
    this.#customerExternalRef = fields.customerExternalRef
    this.#externalRef = fields.externalRef
    this.#fee = fields.fee
    this.#fees = fields.fees
    this.#fromAmount = fields.fromAmount
    Object.freeze(this)
  }

  /** Settled deposit amount. Guaranteed by the service; see the class note. */
  get amount(): Money {
    return this.#amount
  }

  /** Customer-supplied reference (for example, a wire memo). Withheld from default renderings. */
  get customerExternalRef(): string | null {
    return this.#customerExternalRef
  }

  /** External bank reference. Withheld from default renderings. */
  get externalRef(): string | null {
    return this.#externalRef
  }

  /** Legacy singular fee field; populated only when the source projection supplies `fee`. */
  get fee(): Money | null {
    return this.#fee
  }

  /** Detail fee field; populated only when the source projection supplies `fees`. */
  get fees(): Money | null {
    return this.#fees
  }

  /** Pre-conversion amount, present only when a currency conversion applied. */
  get fromAmount(): Money | null {
    return this.#fromAmount
  }

  /** Identifiers, states, and locations render; amounts do not. */
  toJSON(): DepositRendering {
    return {
      amount: this.#amount,
      createDate: this.createDate,
      destination: this.destination,
      fee: this.#fee,
      fees: this.#fees,
      fromAmount: this.#fromAmount,
      id: this.id,
      status: this.status,
    }
  }

  /** Identifiers and states print; amounts do not — each `Money` withholds its own. */
  toString(): string {
    return (
      `Deposit(id=${this.id}, status=${this.status.kind}, ` +
      `destination=${this.destination === null ? 'null' : this.destination.kind}, ` +
      `amount=${String(this.#amount)}, fee=${String(this.#fee)}, fees=${String(this.#fees)})`
    )
  }
}
