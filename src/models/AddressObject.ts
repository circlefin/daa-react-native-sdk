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

/** The redacted shape `JSON.stringify(addressObject)` produces. */
export type AddressObjectRendering = {
  readonly id: string
  readonly address: string
  readonly addressTag: string | null
  readonly currency: string | null
  readonly chain: string
  readonly accountId: string | null
}

/**
 * A DAA deposit address, as the service reports it
 * (`GET /v1/accounts/addresses/deposit/{depositId}`; the `AddressObject`
 * response).
 *
 * **This model exists to carry a blockchain receive address, and that is the
 * field an SDK for self-custody DAA accounts must guard hardest.** `address`
 * and `addressTag` sit behind prototype accessors over `#` private fields
 * rather than own properties — the same technique `Account` uses for
 * `depositAddress` and `Money` uses for `amount` — so `Object.keys`,
 * `JSON.stringify`, `{ ...addressObject }`, `for...in`, and the object
 * inspectors behind `console.log` cannot reach them. `toJSON`/`toString` say
 * the value was withheld rather than omitting it silently — the same choice
 * `Money` makes, and for the same reason: a caller who logs an address object
 * should see that a receive address exists and was not printed, not get back
 * an object that quietly has one field fewer.
 *
 * **Fields the service guarantees are non-null here: `id`, `address`, and
 * `chain`.** That set comes from how the service builds an address for each of
 * its three custody sources — omnibus, segregated, and self — and **not** from
 * the schema, which names only `addressTag` as nullable. The guarantee is
 * narrower than the schema implies:
 *
 * - `addressTag` is genuinely optional: a real value from the omnibus source,
 *   always `null` from segregated and self, matching its documented role as a
 *   memo/destination tag.
 * - **`currency` is `null` on every segregated and self-custody *read*.** Both
 *   sources report a real value only on `create`, which this SDK does not call
 *   here. Only the omnibus source ever returns a real currency from a read. A
 *   model that trusted the schema's silence and made `currency` required would
 *   fail to decode most segregated/self-custody address reads.
 * - `accountId` can be `null`: the omnibus source can return an address it
 *   cannot attribute to an account, which is a state to tolerate, not a
 *   defect.
 *
 * A response missing `id`, `address`, or `chain` is reported as a
 * `contract_violation` rather than decoded into an address with a hole in it
 * — see `wire/addressObjectPayload.ts`.
 *
 * **`currency` and `chain` are plain strings, not closed unions,** for the
 * same reason `Account.blockchain` and `Money.currency` are: both bind to the
 * service's shared chain and currency types, which are large and
 * grow independently of an SDK release, so modelling them as a closed set
 * this SDK controls would reject a real, valid value the day the service adds
 * one. This is a deliberate difference from `CustodyType`/`AccountPurpose`/
 * `AccountStatus`/`AccountType`, the small business-state enums this SDK does
 * discriminate on (see `wire/wireEnums.ts`) — `AddressObject` has no field of
 * that shape.
 *
 * **Not constructible by a consumer.** Exported from `index.ts` as a type
 * only, so no runtime constructor reaches the public entry, and the `#`
 * private fields make the type nominal so an object literal cannot be typed
 * as an `AddressObject` either. Frozen at construction for the same reason
 * `Account` is: `readonly` is erased at compile time and would leave a
 * returned address mutable through a cast.
 */
export class AddressObject {
  /** Service-assigned identifier for this address record. */
  readonly id: string

  /**
   * Currency the address accepts. `null` on every segregated and
   * self-custody read — see the class note. Not sensitive; not redacted.
   */
  readonly currency: string | null

  /** Chain the address is on. Not sensitive; not redacted. */
  readonly chain: string

  /**
   * The DAA account this address belongs to. `null` only when the omnibus
   * source cannot attribute the address to an account — see the class note. Not sensitive; not
   * redacted.
   */
  readonly accountId: string | null

  readonly #address: string
  readonly #addressTag: string | null

  /** @internal Constructed only by the SDK's response decoder. */
  constructor(fields: {
    readonly id: string
    readonly address: string
    readonly addressTag: string | null
    readonly currency: string | null
    readonly chain: string
    readonly accountId: string | null
  }) {
    this.id = fields.id
    this.currency = fields.currency
    this.chain = fields.chain
    this.accountId = fields.accountId
    this.#address = fields.address
    this.#addressTag = fields.addressTag
    Object.freeze(this)
  }

  /**
   * The blockchain receive address. This is the field the SDK exists to
   * report and the one it guards hardest — see the class note.
   */
  get address(): string {
    return this.#address
  }

  /**
   * Secondary on-chain identifier (e.g. a Stellar memo or destination tag).
   * `null` when the chain or custody source has none — see the class note.
   * Redacted the same way `address` is: it is a crypto identifier too.
   */
  get addressTag(): string | null {
    return this.#addressTag
  }

  /**
   * Identifiers and states render; the address and its tag say only that
   * they were withheld — `null` renders as `null` rather than a redaction
   * marker, since there is nothing to redact from an address with no tag.
   */
  toJSON(): AddressObjectRendering {
    return {
      id: this.id,
      address: REDACTED,
      addressTag: this.#addressTag === null ? null : REDACTED,
      currency: this.currency,
      chain: this.chain,
      accountId: this.accountId,
    }
  }

  /** Identifiers and states print; the address and its tag do not. */
  toString(): string {
    return (
      `AddressObject(id=${this.id}, chain=${this.chain}, currency=${this.currency}, ` +
      `accountId=${this.accountId}, address=${REDACTED}, ` +
      `addressTag=${this.#addressTag === null ? null : REDACTED})`
    )
  }
}
