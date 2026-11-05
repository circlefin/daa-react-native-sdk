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

import type { DepositAccountLocation, DepositRiskEvaluation, DepositStatus } from './Deposit'
import type { Money } from './Money'

/** The redacted shape `JSON.stringify(depositSummary)` produces. Every amount is a `Money`, which self-redacts. */
export type DepositSummaryRendering = {
  readonly amount: Money
  readonly createDate: string
  readonly destination: DepositAccountLocation | null
  readonly fee: Money | null
  readonly id: string
  readonly status: DepositStatus
}

/**
 * The compact deposit projection the collection endpoint returns, as the SDK
 * contract's `DepositListQuery` result element
 * (`list(): Promise<Page<DepositSummary>>`).
 *
 * This is deliberately not `Deposit`, and not merely `Deposit` with fields
 * omitted at the type level: the service's `DepositSummary` response has no
 * `source`, `fees`, `fromAmount`, or `trackingRef` property at all, so a
 * decoder that read them off a summary response would either throw on every
 * page or silently invent absence for a field the wire never carries. `fee` on
 * a summary is the coalesced value (`fee` if the source projection supplied
 * one, else `fees`) — the summary has the one fee field, unlike the detail
 * read's separate legacy and detail fee fields.
 *
 * Requiredness mirrors `Deposit`'s class note, because both wire records come
 * from the same two read paths (omnibus and segregated): `id`, `amount`,
 * `status`, and `createDate` are guaranteed; `destination` is optional despite
 * the schema marking it required, because the omnibus path reports `null`
 * whenever the ledger leg is not a wallet — a real code path, not a
 * hypothetical one; `updateDate` is optional and not marked required at all,
 * for the same asymmetric-risk reason `Deposit` gives.
 *
 * Not constructible by a consumer: exported from `index.ts` as a type only,
 * and the `#` private fields make the type nominal.
 */
export class DepositSummary {
  readonly createDate: string
  readonly destination: DepositAccountLocation | null
  readonly errorCode: string | null
  readonly id: string
  readonly riskEvaluation: DepositRiskEvaluation | null
  readonly sourceAccountId: string | null
  readonly status: DepositStatus
  readonly updateDate: string | null

  readonly #amount: Money
  readonly #customerExternalRef: string | null
  readonly #externalRef: string | null
  readonly #fee: Money | null

  /** @internal Constructed only by the SDK's response decoder. */
  constructor(fields: {
    readonly amount: Money
    readonly createDate: string
    readonly customerExternalRef: string | null
    readonly destination: DepositAccountLocation | null
    readonly errorCode: string | null
    readonly externalRef: string | null
    readonly fee: Money | null
    readonly id: string
    readonly riskEvaluation: DepositRiskEvaluation | null
    readonly sourceAccountId: string | null
    readonly status: DepositStatus
    readonly updateDate: string | null
  }) {
    this.createDate = fields.createDate
    this.destination = fields.destination
    this.errorCode = fields.errorCode
    this.id = fields.id
    this.riskEvaluation = fields.riskEvaluation
    this.sourceAccountId = fields.sourceAccountId
    this.status = fields.status
    this.updateDate = fields.updateDate
    this.#amount = fields.amount
    this.#customerExternalRef = fields.customerExternalRef
    this.#externalRef = fields.externalRef
    this.#fee = fields.fee
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

  /** The one fee field a summary carries — see the class note on how it is coalesced. */
  get fee(): Money | null {
    return this.#fee
  }

  /** Identifiers, states, and locations render; amounts do not. */
  toJSON(): DepositSummaryRendering {
    return {
      amount: this.#amount,
      createDate: this.createDate,
      destination: this.destination,
      fee: this.#fee,
      id: this.id,
      status: this.status,
    }
  }

  /** Identifiers and states print; amounts do not — each `Money` withholds its own. */
  toString(): string {
    return (
      `DepositSummary(id=${this.id}, status=${this.status.kind}, ` +
      `destination=${this.destination === null ? 'null' : this.destination.kind}, ` +
      `amount=${String(this.#amount)}, fee=${String(this.#fee)})`
    )
  }
}
