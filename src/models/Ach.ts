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

import { BankAddress, BillingDetails } from './FiatAccount'
import type { FiatAccountStatus } from './FiatAccount'
import { REDACTED } from './redaction'

// `ACH` and `ACHInstruction` follow the component naming of the canonical
// public Accounts OpenAPI's wire schemas, not DAA-owned aliases.
//
// The public Accounts OpenAPI does not publish an ACH schema, so these field
// names are inferred: they mirror `Wire`'s own shape. The ACH beneficiary bank
// is `name`/`accountNumber`/`routingNumber`/`address`/`city`/`country`/
// `postalCode` — no `swiftCode` or `currency`, unlike wire's beneficiary bank,
// because ACH is a domestic-only rail. The one field beyond the wire mirror,
// `ACH.routingNumber`, carries the account's routing information: fiat-account
// list and get responses contain restricted PII, including billing details
// and, **for ACH, routing information**, on the ACH resource itself and not
// only inside its instructions. Check these names against the public ACH
// schema once one is published.

/**
 * Circle's own receiving identity on an ACH instruction. Not redacted, for the
 * same reason `WireInstructionBeneficiary` is not — see that type's doc.
 */
export type ACHInstructionBeneficiary = Readonly<{
  name: string | null
  address1: string | null
  address2: string | null
}>

/**
 * The receiving bank's own account details for an ACH instruction —
 * `routingNumber` and `accountNumber` among them, which are restricted for
 * ACH. Redacted the same way `WireInstructionBeneficiaryBank` is. No
 * `swiftCode`/`currency`: ACH is a domestic US rail (see the file header).
 */
export class ACHInstructionBeneficiaryBank {
  readonly #name: string | null
  readonly #routingNumber: string | null
  readonly #accountNumber: string | null
  readonly #address: string | null
  readonly #city: string | null
  readonly #postalCode: string | null
  readonly #country: string | null

  /** @internal Constructed only by the SDK's response decoder. */
  constructor(fields: {
    readonly name: string | null
    readonly routingNumber: string | null
    readonly accountNumber: string | null
    readonly address: string | null
    readonly city: string | null
    readonly postalCode: string | null
    readonly country: string | null
  }) {
    this.#name = fields.name
    this.#routingNumber = fields.routingNumber
    this.#accountNumber = fields.accountNumber
    this.#address = fields.address
    this.#city = fields.city
    this.#postalCode = fields.postalCode
    this.#country = fields.country
    Object.freeze(this)
  }

  get name(): string | null {
    return this.#name
  }

  get routingNumber(): string | null {
    return this.#routingNumber
  }

  get accountNumber(): string | null {
    return this.#accountNumber
  }

  get address(): string | null {
    return this.#address
  }

  get city(): string | null {
    return this.#city
  }

  get postalCode(): string | null {
    return this.#postalCode
  }

  get country(): string | null {
    return this.#country
  }

  toJSON(): string {
    return this.toString()
  }

  toString(): string {
    return `ACHInstructionBeneficiaryBank(${REDACTED})`
  }
}

/**
 * Circle receiving instructions for an ACH fiat account (`GET
 * /v1/banks/ach/{id}/instructions`).
 *
 * Deliberately a separate SDK method and response type from {@link ACH} — see
 * {@link import('./Wire').WireInstruction}'s doc, which states the same rule
 * for wire. Also a plain typed read of the public route for the same reason:
 * no self-custody pass-through-account resolution happens here, and the ACH
 * route has no public `accountId` parameter to resolve one with.
 */
export class ACHInstruction {
  readonly trackingRef: string | null
  readonly beneficiary: ACHInstructionBeneficiary | null

  readonly #beneficiaryBank: ACHInstructionBeneficiaryBank | null

  /** @internal Constructed only by the SDK's response decoder. */
  constructor(fields: {
    trackingRef: string | null
    beneficiary: ACHInstructionBeneficiary | null
    beneficiaryBank: ACHInstructionBeneficiaryBank | null
  }) {
    this.trackingRef = fields.trackingRef
    this.beneficiary = fields.beneficiary
    this.#beneficiaryBank = fields.beneficiaryBank
    Object.freeze(this)
  }

  get beneficiaryBank(): ACHInstructionBeneficiaryBank | null {
    return this.#beneficiaryBank
  }

  toJSON(): {
    trackingRef: string | null
    beneficiary: ACHInstructionBeneficiary | null
    beneficiaryBank: string | null
  } {
    return {
      trackingRef: this.trackingRef,
      beneficiary: this.beneficiary,
      beneficiaryBank: this.#beneficiaryBank === null ? null : REDACTED,
    }
  }

  toString(): string {
    return (
      `ACHInstruction(trackingRef=${this.trackingRef ?? 'null'}, ` +
      `beneficiaryBank=${this.#beneficiaryBank === null ? 'null' : REDACTED})`
    )
  }
}

/**
 * An ACH fiat account. This single type serves both `ach.list()` and
 * `ach.get()`: the list returns the full `ACH` projection for consistency with
 * the by-id read, unlike wire's separate `WireSummary`/`Wire` list/get pair.
 *
 * `billingDetails`, `bankAddress`, and `routingNumber` are private, redacted
 * fields — all three are restricted for ACH. See the file header for
 * `routingNumber`.
 */
export class ACH {
  readonly id: string
  readonly type: string | null
  readonly status: FiatAccountStatus
  readonly description: string
  readonly trackingRef: string
  readonly fingerprint: string
  readonly createDate: string
  readonly updateDate: string

  readonly #billingDetails: BillingDetails
  readonly #bankAddress: BankAddress | null
  readonly #routingNumber: string | null

  /** @internal Constructed only by the SDK's response decoder. */
  constructor(fields: {
    id: string
    type: string | null
    status: FiatAccountStatus
    description: string
    trackingRef: string
    fingerprint: string
    billingDetails: BillingDetails
    bankAddress: BankAddress | null
    routingNumber: string | null
    createDate: string
    updateDate: string
  }) {
    this.id = fields.id
    this.type = fields.type
    this.status = fields.status
    this.description = fields.description
    this.trackingRef = fields.trackingRef
    this.fingerprint = fields.fingerprint
    this.createDate = fields.createDate
    this.updateDate = fields.updateDate
    this.#billingDetails = fields.billingDetails
    this.#bankAddress = fields.bankAddress
    this.#routingNumber = fields.routingNumber
    Object.freeze(this)
  }

  get billingDetails(): BillingDetails {
    return this.#billingDetails
  }

  get bankAddress(): BankAddress | null {
    return this.#bankAddress
  }

  get routingNumber(): string | null {
    return this.#routingNumber
  }

  toJSON(): {
    id: string
    type: string | null
    status: FiatAccountStatus
    description: string
    trackingRef: string
    fingerprint: string
    billingDetails: string
    bankAddress: string | null
    routingNumber: string | null
    createDate: string
    updateDate: string
  } {
    return {
      id: this.id,
      type: this.type,
      status: this.status,
      description: this.description,
      trackingRef: this.trackingRef,
      fingerprint: this.fingerprint,
      billingDetails: REDACTED,
      bankAddress: this.#bankAddress === null ? null : REDACTED,
      routingNumber: this.#routingNumber === null ? null : REDACTED,
      createDate: this.createDate,
      updateDate: this.updateDate,
    }
  }

  toString(): string {
    return (
      `ACH(id=${this.id}, status=${this.status.kind}, billingDetails=${REDACTED}, ` +
      `bankAddress=${this.#bankAddress === null ? 'null' : REDACTED}, ` +
      `routingNumber=${this.#routingNumber === null ? 'null' : REDACTED})`
    )
  }
}
