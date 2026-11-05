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
import { REDACTED } from './redaction'

export type WithdrawalStatus =
  | { readonly kind: 'pending' }
  | { readonly kind: 'complete' }
  | { readonly kind: 'failed' }
  | { readonly kind: 'unrecognized'; readonly rawValue: string | null }

export type WithdrawalErrorCode =
  | { readonly kind: 'insufficient_funds' }
  | { readonly kind: 'transaction_denied' }
  | { readonly kind: 'transaction_failed' }
  | { readonly kind: 'transaction_returned' }
  | { readonly kind: 'bank_transaction_error' }
  | { readonly kind: 'fiat_account_limit_exceeded' }
  | { readonly kind: 'invalid_bank_account_number' }
  | { readonly kind: 'invalid_ach_rtn' }
  | { readonly kind: 'invalid_wire_rtn' }
  | { readonly kind: 'vendor_inactive' }
  | { readonly kind: 'payout_canceled' }
  | { readonly kind: 'invalid_travel_rule_identity' }
  | { readonly kind: 'intermediary_bank_required' }
  | { readonly kind: 'sen_not_supported' }
  | { readonly kind: 'unrecognized'; readonly rawValue: string | null }

export type WithdrawalDestinationType =
  | { readonly kind: 'wire' }
  | { readonly kind: 'ach' }
  | { readonly kind: 'unrecognized'; readonly rawValue: string | null }

export type WithdrawalDestination = Readonly<{
  type: WithdrawalDestinationType
  id: string
  name: string | null
}>

export type WithdrawalRiskEvaluation = Readonly<{
  decision: string | null
  reason: string | null
}>

export type WithdrawalPolicyEvaluation = Readonly<{ status: string }>

/** Target fiat amount. Unlike `Money`, its service-side amount is deliberately optional. */
export class WithdrawalToAmount {
  readonly currency: string | null
  readonly #amount: string | null

  /** @internal Constructed only by the response decoder. */
  constructor(amount: string | null, currency: string | null) {
    this.#amount = amount
    this.currency = currency
    Object.freeze(this)
  }

  get amount(): string | null {
    return this.#amount
  }

  toJSON(): { readonly amount: string | null; readonly currency: string | null } {
    return { amount: this.#amount === null ? null : REDACTED, currency: this.currency }
  }

  toString(): string {
    return `WithdrawalToAmount(amount=${this.#amount === null ? 'null' : REDACTED}, currency=${this.currency})`
  }
}

export type WithdrawalAdjustments = Readonly<{
  fxCredit: Money | null
  fxDebit: Money | null
}>

export type WithdrawalReturn = Readonly<{
  id: string | null
  payoutId: string | null
  amount: Money | null
  fees: Money | null
  reason: string | null
  status: WithdrawalStatus | null
  createDate: string | null
  updateDate: string | null
}>

export type WithdrawalSweepStatus =
  | { readonly kind: 'pending' }
  | { readonly kind: 'complete' }
  | { readonly kind: 'failed' }
  | { readonly kind: 'skipped' }
  | { readonly kind: 'unrecognized'; readonly rawValue: string | null }

export type WithdrawalSubAccountSweep = Readonly<{
  subAccountId: string | null
  amount: Money | null
  status: WithdrawalSweepStatus | null
}>

export type WithdrawalDetailRendering = Readonly<{
  id: string
  sourceAccountId: string
  destination: WithdrawalDestination
  amount: ReturnType<Money['toJSON']>
  toAmount: WithdrawalToAmount | null
  fees: ReturnType<Money['toJSON']> | null
  status: WithdrawalStatus
  trackingRef: string | null
  errorCode: WithdrawalErrorCode | null
  externalRef: string | null
  riskEvaluation: WithdrawalRiskEvaluation | null
  adjustments: string
  return: string
  customerExternalRef: string | null
  burnAll: boolean | null
  subAccountSweeps: string
  createDate: string
  updateDate: string | null
  policyEvaluation: WithdrawalPolicyEvaluation | null
}>

/**
 * GET-only DAA withdrawal projection.
 *
 * The guaranteed core follows the service's two read paths, not the generated
 * schema: `id`, `sourceAccountId`, `destination`, `amount`, `status`, and
 * `createDate` are produced by both payout-backed and stored-withdrawal reads.
 * Enrichment is omitted from the response whenever unavailable. Amounts plus
 * bank/customer references are private so object inspection, spread, and
 * enumeration cannot disclose them.
 */
export class WithdrawalDetail {
  readonly id: string
  readonly sourceAccountId: string
  readonly destination: WithdrawalDestination
  readonly status: WithdrawalStatus
  readonly trackingRef: string | null
  readonly errorCode: WithdrawalErrorCode | null
  readonly riskEvaluation: WithdrawalRiskEvaluation | null
  readonly burnAll: boolean | null
  readonly createDate: string
  readonly updateDate: string | null
  readonly policyEvaluation: WithdrawalPolicyEvaluation | null

  readonly #amount: Money
  readonly #toAmount: WithdrawalToAmount | null
  readonly #fees: Money | null
  readonly #externalRef: string | null
  readonly #adjustments: WithdrawalAdjustments | null
  readonly #returnObject: WithdrawalReturn | null
  readonly #customerExternalRef: string | null
  readonly #subAccountSweeps: readonly WithdrawalSubAccountSweep[]

  /** @internal Constructed only by the response decoder. */
  constructor(fields: {
    id: string
    sourceAccountId: string
    destination: WithdrawalDestination
    amount: Money
    toAmount: WithdrawalToAmount | null
    fees: Money | null
    status: WithdrawalStatus
    trackingRef: string | null
    errorCode: WithdrawalErrorCode | null
    externalRef: string | null
    riskEvaluation: WithdrawalRiskEvaluation | null
    adjustments: WithdrawalAdjustments | null
    returnObject: WithdrawalReturn | null
    customerExternalRef: string | null
    burnAll: boolean | null
    subAccountSweeps: readonly WithdrawalSubAccountSweep[]
    createDate: string
    updateDate: string | null
    policyEvaluation: WithdrawalPolicyEvaluation | null
  }) {
    this.id = fields.id
    this.sourceAccountId = fields.sourceAccountId
    this.destination = fields.destination
    this.status = fields.status
    this.trackingRef = fields.trackingRef
    this.errorCode = fields.errorCode
    this.riskEvaluation = fields.riskEvaluation
    this.burnAll = fields.burnAll
    this.createDate = fields.createDate
    this.updateDate = fields.updateDate
    this.policyEvaluation = fields.policyEvaluation
    this.#amount = fields.amount
    this.#toAmount = fields.toAmount
    this.#fees = fields.fees
    this.#externalRef = fields.externalRef
    this.#adjustments = fields.adjustments
    this.#returnObject = fields.returnObject
    this.#customerExternalRef = fields.customerExternalRef
    this.#subAccountSweeps = Object.freeze(fields.subAccountSweeps.slice())
    Object.freeze(this)
  }

  get amount(): Money {
    return this.#amount
  }

  get toAmount(): WithdrawalToAmount | null {
    return this.#toAmount
  }

  get fees(): Money | null {
    return this.#fees
  }

  get externalRef(): string | null {
    return this.#externalRef
  }

  get adjustments(): WithdrawalAdjustments | null {
    return this.#adjustments
  }

  get returnObject(): WithdrawalReturn | null {
    return this.#returnObject
  }

  get customerExternalRef(): string | null {
    return this.#customerExternalRef
  }

  get subAccountSweeps(): readonly WithdrawalSubAccountSweep[] {
    return this.#subAccountSweeps
  }

  toJSON(): WithdrawalDetailRendering {
    return {
      id: this.id,
      sourceAccountId: this.sourceAccountId,
      destination: this.destination,
      amount: this.#amount.toJSON(),
      toAmount: this.#toAmount,
      fees: this.#fees?.toJSON() ?? null,
      status: this.status,
      trackingRef: this.trackingRef,
      errorCode: this.errorCode,
      externalRef: this.#externalRef === null ? null : REDACTED,
      riskEvaluation: this.riskEvaluation,
      adjustments: `${this.#adjustments === null ? 0 : 1} entry`,
      return: `${this.#returnObject === null ? 0 : 1} entry`,
      customerExternalRef: this.#customerExternalRef === null ? null : REDACTED,
      burnAll: this.burnAll,
      subAccountSweeps: `${this.#subAccountSweeps.length} entries`,
      createDate: this.createDate,
      updateDate: this.updateDate,
      policyEvaluation: this.policyEvaluation,
    }
  }

  toString(): string {
    return (
      `WithdrawalDetail(id=${this.id}, sourceAccountId=${this.sourceAccountId}, ` +
      `status=${this.status.kind}, amount=${this.#amount.toString()}, ` +
      `fees=${this.#fees === null ? 'null' : this.#fees.toString()}, ` +
      `externalRef=${this.#externalRef === null ? 'null' : REDACTED}, ` +
      `customerExternalRef=${this.#customerExternalRef === null ? 'null' : REDACTED}, ` +
      `adjustments=${this.#adjustments === null ? 0 : 1} entry, ` +
      `return=${this.#returnObject === null ? 0 : 1} entry, ` +
      `subAccountSweeps=${this.#subAccountSweeps.length} entries)`
    )
  }
}
