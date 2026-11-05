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

import type { BusinessPii } from './BusinessPii'
import type { Money } from './Money'

// The four closed-set fields on an account.
//
// Each is a discriminated union on `kind` — the shape `DaaSdkError` already uses
// in this SDK — rather than a string-literal union. A string-literal union has no
// room for the value the service will add next: decoding into one would either
// throw (leaving this SDK unable to read *any* account because one custody type
// was added service-side) or silently widen to `string`, which discards the
// closed set the type exists to express.
//
// An unfamiliar **present** value degrades to `unrecognized` **carrying the raw
// string**, per the SDK contract's requirement to preserve it "as an
// unknown/raw-value case instead of failing the entire response". Not failing is
// half of that; a bare `unknown` marker satisfies that half and throws away what
// arrived, leaving nobody able to answer why an account read as unknown.
//
// `rawValue` is `null` only where an absent field is tolerated, which is
// `custodyType` alone — see `Account`.

/**
 * How an account's keys are held.
 *
 * The OpenAPI marks `custodyType` as the discriminator for `Account` but supplies
 * no `mapping`, and declares variant schemas for `omnibus` and `segregated` only
 * — it omits the self-custody one entirely, so a client generated from it would
 * produce a union with no arm for the custody type this SDK exists for. The
 * service's responses do carry all three, including self-custody accounts, so
 * the flat model here follows the service's responses rather than the schema.
 */
export type CustodyType =
  | { readonly kind: 'omnibus' }
  | { readonly kind: 'segregated' }
  /** A non-custodial account: the device key authorizes custody changes. */
  | { readonly kind: 'self' }
  | { readonly kind: 'unrecognized'; readonly rawValue: string | null }

/** What the account is for. */
export type AccountPurpose =
  | { readonly kind: 'custody' }
  | { readonly kind: 'payments' }
  | { readonly kind: 'unrecognized'; readonly rawValue: string | null }

/** Where the account is in its lifecycle. A created account starts `pending`. */
export type AccountStatus =
  | { readonly kind: 'active' }
  | { readonly kind: 'pending' }
  | { readonly kind: 'rejected' }
  | { readonly kind: 'archived' }
  | { readonly kind: 'unrecognized'; readonly rawValue: string | null }

/** Whether the account is held for the entity itself or on behalf of another. */
export type AccountType =
  | { readonly kind: 'first_party' }
  | { readonly kind: 'third_party' }
  | { readonly kind: 'unrecognized'; readonly rawValue: string | null }

/** The redacted shape `JSON.stringify(account)` produces. */
export type AccountRendering = {
  readonly accountId: string
  readonly balances: string
  readonly blockchain: string | null
  readonly custodyType: CustodyType
  readonly purpose: AccountPurpose
  readonly status: AccountStatus
  readonly type: AccountType
}

/**
 * A DAA account, as the service reports it.
 *
 * Read-only at runtime as well as in the type system: the instance is frozen and
 * `balances` is a frozen array, because `readonly` is erased at compile time and
 * would leave a returned account mutable through a cast.
 *
 * **Not constructible by a consumer.** This class is exported from `index.ts` as
 * a **type only**, so no runtime constructor reaches the public entry, and the
 * `#` private fields make the type nominal so an object literal cannot be typed
 * as an `Account` either. Every instance a caller holds came from a response
 * this SDK decoded — the same rule the error model follows, and for the same
 * reason: code downstream treats these values as server-attributed.
 *
 * **Fields the service guarantees are non-null here.** A response missing one is
 * reported as a `contract_violation` rather than decoded into an account with
 * holes in it. Making everything nullable would turn a service defect into an SDK
 * *success* and push the null handling onto every caller — a `200` with an empty
 * body would arrive as a cheerful empty account. Tolerating unknown *additional*
 * fields and preserving an unfamiliar *present* closed-set value are forward
 * compatibility; accepting a missing required value is not.
 *
 * The guaranteed set comes from the service's own nullability contract —
 * `accountId`, `balances`, `entityId`, `purpose`, `status`, and `type` are
 * never null in what it serialises — and **not** from the OpenAPI's
 * `required:` block. Nothing validates a response against that block, and it
 * lists fields the service genuinely omits.
 *
 * **Balances and the receive address do not appear in any default rendering.**
 * They sit behind prototype accessors rather than own properties, so
 * `Object.keys`, `JSON.stringify`, `{ ...account }`, `for...in`, and the object
 * inspectors behind `console.log` do not reach them; `toString` and `toJSON`
 * reduce balances to a count and omit the rest. The service excludes the same
 * fields from its own rendering.
 *
 * That is a control over *default* rendering, not a capability: an inspector
 * explicitly asked to evaluate prototype accessors
 * (`util.inspect(account, { showHidden: true, getters: true })`) reveals them, and
 * a consumer reading `balances[0].amount` and logging it is doing so deliberately.
 * What is prevented is a balance reaching a log by accident — through a crash
 * reporter, a `console.log(account)`, or a `JSON.stringify` of a state tree.
 */
export class Account {
  /** Service-assigned identifier. */
  readonly accountId: string

  /**
   * The account's immutable home chain, as returned by the account API.
   *
   * A plain string because the SDK contract declares it `blockchain?: string` and
   * new chains ship without an SDK release. `null` when the service sent none;
   * the contract states DAA provisions on `ARC` when the field is omitted at
   * creation, but that default is the service's to apply and is not invented
   * here. Present on self-custody and segregated accounts.
   */
  readonly blockchain: string | null

  /** Set only for a `self` custody type; identifies the entity whose keys hold the account. */
  readonly clientEntityId: string | null

  /** How the keys are held. `self` is a non-custodial account whose device key authorizes custody changes. */
  readonly custodyType: CustodyType

  /**
   * Caller-supplied label, absent when none was set.
   *
   * Optional despite the OpenAPI listing it as required. The service treats
   * this field as nullable, like `clientEntityId` and `groupId`, and the
   * service creates accounts without a description. A response omitting it is
   * ordinary, not malformed.
   */
  readonly description: string | null

  /** The owning entity. */
  readonly entityId: string

  /** Nullable on the wire as well as absent — the contract marks it so. */
  readonly groupId: string | null

  readonly purpose: AccountPurpose

  readonly status: AccountStatus

  readonly type: AccountType

  readonly #balances: readonly Money[]
  readonly #businessPii: BusinessPii | null
  readonly #depositAddress: string | null

  /** @internal Constructed only by the SDK's response decoder. */
  constructor(fields: {
    readonly accountId: string
    readonly balances: readonly Money[]
    readonly blockchain: string | null
    readonly businessPii: BusinessPii | null
    readonly clientEntityId: string | null
    readonly custodyType: CustodyType
    readonly depositAddress: string | null
    readonly description: string | null
    readonly entityId: string
    readonly groupId: string | null
    readonly purpose: AccountPurpose
    readonly status: AccountStatus
    readonly type: AccountType
  }) {
    this.accountId = fields.accountId
    this.blockchain = fields.blockchain
    this.clientEntityId = fields.clientEntityId
    this.custodyType = fields.custodyType
    this.description = fields.description
    this.entityId = fields.entityId
    this.groupId = fields.groupId
    this.purpose = fields.purpose
    this.status = fields.status
    this.type = fields.type
    // The array is copied before freezing so the caller's own array is not
    // frozen. The freeze itself is pinned by a test.
    this.#balances = Object.freeze(fields.balances.slice())
    this.#businessPii = fields.businessPii
    this.#depositAddress = fields.depositAddress
    Object.freeze(this)
  }

  /** Balances held, one entry per currency. Empty when the service sent none. */
  get balances(): readonly Money[] {
    return this.#balances
  }

  /**
   * Business identity enrichment, on eligible omnibus reads only.
   *
   * Never present on a self-custody account. See `BusinessPii`.
   */
  get businessPii(): BusinessPii | null {
    return this.#businessPii
  }

  /**
   * The established receive address for a self-custody or segregated account.
   *
   * `null` until the provider mapping is active and complete, which is the
   * service's own wording — an account can exist before it has a routable
   * address, so absence is a state rather than an error. For a self-custody
   * consumer this is the field the account is *for*.
   */
  get depositAddress(): string | null {
    return this.#depositAddress
  }

  /** Identifiers and states render; values do not. */
  toJSON(): AccountRendering {
    return {
      accountId: this.accountId,
      balances: `${this.#balances.length} entries`,
      blockchain: this.blockchain,
      custodyType: this.custodyType,
      purpose: this.purpose,
      status: this.status,
      type: this.type,
    }
  }

  /**
   * Identifiers and states print; values do not.
   *
   * `depositAddress` is excluded because it is the account's receive address, and
   * balances are reduced to a count. `businessPii` is not referenced at all.
   */
  toString(): string {
    return (
      `Account(accountId=${this.accountId}, blockchain=${this.blockchain}, ` +
      `custodyType=${this.custodyType.kind}, purpose=${this.purpose.kind}, ` +
      `status=${this.status.kind}, type=${this.type.kind}, ` +
      `balances=${this.#balances.length} entries)`
    )
  }
}
