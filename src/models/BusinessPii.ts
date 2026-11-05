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

/**
 * A postal address, as the DAA API reports it.
 *
 * Every field is optional. The OpenAPI marks several required, but the service
 * populates them best-effort from customer records — an absent source attribute
 * simply leaves the field null — and omits nulls from the JSON. Requiring any of
 * them would make an account with incomplete enrichment fail to read at all.
 *
 * **Nothing is rendered.** Every field is identity data, so all of them sit
 * behind prototype accessors rather than own properties: `Object.keys`,
 * `{ ...address }`, `for...in`, and the inspectors behind `console.log` see an
 * empty object, and `toJSON` returns a redaction marker so `JSON.stringify` does
 * too. A rendering exists so a log line naming the type is still useful, not so
 * the address travels with it.
 */
export class Address {
  readonly #city: string | null
  readonly #country: string | null
  readonly #district: string | null
  readonly #line1: string | null
  readonly #line2: string | null
  readonly #postalCode: string | null

  /** @internal Constructed only by the SDK's response decoder. */
  constructor(fields: {
    readonly city: string | null
    readonly country: string | null
    readonly district: string | null
    readonly line1: string | null
    readonly line2: string | null
    readonly postalCode: string | null
  }) {
    this.#city = fields.city
    this.#country = fields.country
    this.#district = fields.district
    this.#line1 = fields.line1
    this.#line2 = fields.line2
    this.#postalCode = fields.postalCode
    Object.freeze(this)
  }

  get city(): string | null {
    return this.#city
  }

  get country(): string | null {
    return this.#country
  }

  get district(): string | null {
    return this.#district
  }

  get line1(): string | null {
    return this.#line1
  }

  get line2(): string | null {
    return this.#line2
  }

  get postalCode(): string | null {
    return this.#postalCode
  }

  toJSON(): string {
    return this.toString()
  }

  toString(): string {
    return `Address(${REDACTED})`
  }
}

/**
 * Business identity enrichment attached to an account.
 *
 * The service sends this only on eligible omnibus read responses — the contract
 * scopes it to `first_party` attributed accounts with `payments` purpose, absent
 * on create, archive, segregated, and ineligible responses. It is therefore
 * never present on the self-custody accounts this SDK exists for, and a consumer
 * should expect `null` in practice.
 *
 * It is modelled rather than discarded because the endpoint this SDK calls
 * returns it, and silently dropping a field the service sent would hide it
 * from the caller.
 *
 * Redacted the same way [Address] is, and for the same reason. The service
 * excludes the same field from its own rendering.
 */
export class BusinessPii {
  readonly #address: Address | null
  readonly #businessName: string | null
  readonly #businessUniqueIdentifier: string | null
  readonly #identifierIssuingCountryCode: string | null

  /** @internal Constructed only by the SDK's response decoder. */
  constructor(fields: {
    readonly address: Address | null
    readonly businessName: string | null
    readonly businessUniqueIdentifier: string | null
    readonly identifierIssuingCountryCode: string | null
  }) {
    this.#address = fields.address
    this.#businessName = fields.businessName
    this.#businessUniqueIdentifier = fields.businessUniqueIdentifier
    this.#identifierIssuingCountryCode = fields.identifierIssuingCountryCode
    Object.freeze(this)
  }

  get address(): Address | null {
    return this.#address
  }

  get businessName(): string | null {
    return this.#businessName
  }

  get businessUniqueIdentifier(): string | null {
    return this.#businessUniqueIdentifier
  }

  get identifierIssuingCountryCode(): string | null {
    return this.#identifierIssuingCountryCode
  }

  toJSON(): string {
    return this.toString()
  }

  toString(): string {
    return `BusinessPii(${REDACTED})`
  }
}
