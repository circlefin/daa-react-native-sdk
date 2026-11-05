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

// `WireSummary`, `Wire`, and `WireInstruction` are the exact component names
// the canonical public Accounts OpenAPI uses, not DAA-owned aliases.
// `WireInstructionBeneficiary` and `WireInstructionBeneficiaryBank` are that
// same schema's own nested type names for `WireInstruction`'s
// `beneficiary`/`beneficiaryBank` properties.

/** One `transferTypesInfo` entry: the currencies a supported transfer type accepts. */
export type TransferTypeInfo = Readonly<{
  currencies: readonly string[]
}>

/**
 * Circle's own receiving identity on a wire instruction — who the wire is
 * addressed to, not the fiat-account holder. Not redacted: this is Circle's
 * published receiving name and address, the same information the wire
 * reference text itself carries, not the restricted PII this SDK redacts
 * (`billingDetails`, `bankAddress`, `routingNumber`).
 */
export type WireInstructionBeneficiary = Readonly<{
  name: string | null
  address1: string | null
  address2: string | null
}>

/**
 * The receiving bank's own account details for a wire instruction —
 * `routingNumber` and `accountNumber` among them, which are restricted PII.
 * Redacted the same way
 * `models/FiatAccount.ts`'s `BillingDetails`/`BankAddress` are.
 */
export class WireInstructionBeneficiaryBank {
  readonly #name: string | null
  readonly #swiftCode: string | null
  readonly #routingNumber: string | null
  readonly #accountNumber: string | null
  readonly #currency: string | null
  readonly #address: string | null
  readonly #city: string | null
  readonly #postalCode: string | null
  readonly #country: string | null

  /** @internal Constructed only by the SDK's response decoder. */
  constructor(fields: {
    readonly name: string | null
    readonly swiftCode: string | null
    readonly routingNumber: string | null
    readonly accountNumber: string | null
    readonly currency: string | null
    readonly address: string | null
    readonly city: string | null
    readonly postalCode: string | null
    readonly country: string | null
  }) {
    this.#name = fields.name
    this.#swiftCode = fields.swiftCode
    this.#routingNumber = fields.routingNumber
    this.#accountNumber = fields.accountNumber
    this.#currency = fields.currency
    this.#address = fields.address
    this.#city = fields.city
    this.#postalCode = fields.postalCode
    this.#country = fields.country
    Object.freeze(this)
  }

  get name(): string | null {
    return this.#name
  }

  get swiftCode(): string | null {
    return this.#swiftCode
  }

  get routingNumber(): string | null {
    return this.#routingNumber
  }

  get accountNumber(): string | null {
    return this.#accountNumber
  }

  get currency(): string | null {
    return this.#currency
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
    return `WireInstructionBeneficiaryBank(${REDACTED})`
  }
}

/**
 * Circle receiving instructions for a wire fiat account (`GET
 * /v1/banks/wires/{id}/instructions`).
 *
 * Deliberately a separate SDK method and response type from {@link Wire}: the
 * account resource and its funding instructions are separate. This is a plain
 * typed read of the public instruction route, which returns Circle's receiving
 * instructions; it does not resolve a self-custody pass-through account.
 */
export class WireInstruction {
  readonly trackingRef: string | null
  readonly beneficiary: WireInstructionBeneficiary | null
  readonly virtualAccountEnabled: boolean | null

  readonly #beneficiaryBank: WireInstructionBeneficiaryBank | null

  /** @internal Constructed only by the SDK's response decoder. */
  constructor(fields: {
    trackingRef: string | null
    beneficiary: WireInstructionBeneficiary | null
    beneficiaryBank: WireInstructionBeneficiaryBank | null
    virtualAccountEnabled: boolean | null
  }) {
    this.trackingRef = fields.trackingRef
    this.beneficiary = fields.beneficiary
    this.virtualAccountEnabled = fields.virtualAccountEnabled
    this.#beneficiaryBank = fields.beneficiaryBank
    Object.freeze(this)
  }

  get beneficiaryBank(): WireInstructionBeneficiaryBank | null {
    return this.#beneficiaryBank
  }

  toJSON(): {
    trackingRef: string | null
    beneficiary: WireInstructionBeneficiary | null
    beneficiaryBank: string | null
    virtualAccountEnabled: boolean | null
  } {
    return {
      trackingRef: this.trackingRef,
      beneficiary: this.beneficiary,
      beneficiaryBank: this.#beneficiaryBank === null ? null : REDACTED,
      virtualAccountEnabled: this.virtualAccountEnabled,
    }
  }

  toString(): string {
    return (
      `WireInstruction(trackingRef=${this.trackingRef ?? 'null'}, ` +
      `beneficiaryBank=${this.#beneficiaryBank === null ? 'null' : REDACTED})`
    )
  }
}

/**
 * A wire bank account summary (`GET /v1/banks/wires` collection entry).
 *
 * `billingDetails` and `bankAddress` are private, redacted fields — see
 * `models/FiatAccount.ts`. `ffcMemo` is private and redacted the same way: it
 * is not one of the named restricted fields, but a for-further-credit memo can
 * carry the end beneficiary's name, which is the same personal data
 * `billingDetails.name` holds. Every other field is public:
 * `id`/`status`/`description` (bank name plus last four
 * digits)/`trackingRef`/`fingerprint` are what a caller needs to identify and
 * select a fiat account without exposing the underlying bank details.
 */
export class WireSummary {
  readonly id: string
  readonly type: string | null
  readonly status: FiatAccountStatus
  readonly description: string
  readonly trackingRef: string
  readonly fingerprint: string
  readonly virtualAccountEnabled: boolean | null
  readonly createDate: string
  readonly updateDate: string

  readonly #billingDetails: BillingDetails
  readonly #bankAddress: BankAddress | null
  readonly #ffcMemo: string | null

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
    virtualAccountEnabled: boolean | null
    ffcMemo: string | null
    createDate: string
    updateDate: string
  }) {
    this.id = fields.id
    this.type = fields.type
    this.status = fields.status
    this.description = fields.description
    this.trackingRef = fields.trackingRef
    this.fingerprint = fields.fingerprint
    this.virtualAccountEnabled = fields.virtualAccountEnabled
    this.createDate = fields.createDate
    this.updateDate = fields.updateDate
    this.#billingDetails = fields.billingDetails
    this.#bankAddress = fields.bankAddress
    this.#ffcMemo = fields.ffcMemo
    Object.freeze(this)
  }

  get billingDetails(): BillingDetails {
    return this.#billingDetails
  }

  get bankAddress(): BankAddress | null {
    return this.#bankAddress
  }

  get ffcMemo(): string | null {
    return this.#ffcMemo
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
    virtualAccountEnabled: boolean | null
    ffcMemo: string | null
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
      virtualAccountEnabled: this.virtualAccountEnabled,
      ffcMemo: this.#ffcMemo === null ? null : REDACTED,
      createDate: this.createDate,
      updateDate: this.updateDate,
    }
  }

  toString(): string {
    return (
      `WireSummary(id=${this.id}, status=${this.status.kind}, ` +
      `billingDetails=${REDACTED}, bankAddress=${this.#bankAddress === null ? 'null' : REDACTED})`
    )
  }
}

/**
 * A wire bank account (`GET /v1/banks/wires/{id}`).
 *
 * Carries every {@link WireSummary} field plus `transferTypesInfo`, which the
 * list projection omits, and redacts `billingDetails`, `bankAddress`, and
 * `ffcMemo` the same way. Deliberately a distinct SDK type from `WireSummary`
 * rather than a subtype — fiat-account resources are distinct SDK methods and
 * response types, and the two
 * projections diverge only in this one additional field, not in a
 * specialization relationship.
 */
export class Wire {
  readonly id: string
  readonly type: string | null
  readonly status: FiatAccountStatus
  readonly description: string
  readonly trackingRef: string
  readonly fingerprint: string
  readonly virtualAccountEnabled: boolean | null
  readonly transferTypesInfo: Readonly<Record<string, TransferTypeInfo>> | null
  readonly createDate: string
  readonly updateDate: string

  readonly #billingDetails: BillingDetails
  readonly #bankAddress: BankAddress | null
  readonly #ffcMemo: string | null

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
    virtualAccountEnabled: boolean | null
    ffcMemo: string | null
    transferTypesInfo: Readonly<Record<string, TransferTypeInfo>> | null
    createDate: string
    updateDate: string
  }) {
    this.id = fields.id
    this.type = fields.type
    this.status = fields.status
    this.description = fields.description
    this.trackingRef = fields.trackingRef
    this.fingerprint = fields.fingerprint
    this.virtualAccountEnabled = fields.virtualAccountEnabled
    this.transferTypesInfo = fields.transferTypesInfo
    this.createDate = fields.createDate
    this.updateDate = fields.updateDate
    this.#billingDetails = fields.billingDetails
    this.#bankAddress = fields.bankAddress
    this.#ffcMemo = fields.ffcMemo
    Object.freeze(this)
  }

  get billingDetails(): BillingDetails {
    return this.#billingDetails
  }

  get bankAddress(): BankAddress | null {
    return this.#bankAddress
  }

  get ffcMemo(): string | null {
    return this.#ffcMemo
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
    virtualAccountEnabled: boolean | null
    ffcMemo: string | null
    transferTypesInfo: Readonly<Record<string, TransferTypeInfo>> | null
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
      virtualAccountEnabled: this.virtualAccountEnabled,
      ffcMemo: this.#ffcMemo === null ? null : REDACTED,
      transferTypesInfo: this.transferTypesInfo,
      createDate: this.createDate,
      updateDate: this.updateDate,
    }
  }

  toString(): string {
    return (
      `Wire(id=${this.id}, status=${this.status.kind}, ` +
      `billingDetails=${REDACTED}, bankAddress=${this.#bankAddress === null ? 'null' : REDACTED})`
    )
  }
}
