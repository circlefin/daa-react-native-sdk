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

// A DAA transaction's closed-set fields and its polymorphic source/destination
// legs. Same posture as `Transfer`: a discriminated union on `kind` rather than
// a string-literal union, so a value the service adds later degrades to
// `unrecognized` instead of failing the whole row.
//
// This is the unified activity row (OpenAPI `Transaction`) returned by
// `GET /v1/accounts/transactions`. Unlike `Transfer`, a transaction leg may be
// a fiat rail (`wire`/`ach`), and both `source` and `destination` are optional
// ("present when available"). `status` adds `returned` over the transfer set.

/**
 * Where a transaction is in its lifecycle (OpenAPI `TransactionStatus`).
 *
 * A superset of `TransferStatus`: unified account activity adds `returned`
 * (e.g. a returned deposit).
 */
export type TransactionStatus =
  | { readonly kind: 'pending' }
  | { readonly kind: 'complete' }
  | { readonly kind: 'failed' }
  | { readonly kind: 'returned' }
  | { readonly kind: 'unrecognized'; readonly rawValue: string | null }

/**
 * Coarse activity kind (OpenAPI `TransactionType`).
 *
 * This is the user-facing taxonomy the service already collapses its internal
 * types onto. An unmapped present value degrades to `unrecognized` here; the service
 * itself folds unknown upstream types to `other` before they reach the wire.
 */
export type TransactionType =
  | { readonly kind: 'deposit' }
  | { readonly kind: 'withdrawal' }
  | { readonly kind: 'transfer' }
  | { readonly kind: 'fx' }
  | { readonly kind: 'fee' }
  | { readonly kind: 'credit' }
  | { readonly kind: 'other' }
  | { readonly kind: 'unrecognized'; readonly rawValue: string | null }

/**
 * An account transaction leg (OpenAPI `TransactionDestinationAccountLocation`
 * / `TransferSourceAccountLocation`). Named `accountId` so it is not confused
 * with the transaction's own `id`.
 *
 * The service always reports an account leg here with only its id, so the
 * crypto `address`/`addressTag` a transfer destination can carry are not part
 * of this shape. Unknown extra fields are ignored on the way in.
 */
export type TransactionAccountLocation = {
  readonly kind: 'account'
  readonly accountId: string
}

/** The redacted shape `JSON.stringify`/`toString` produce for a blockchain leg. */
export type TransactionBlockchainLocationRendering = {
  readonly kind: 'blockchain'
  readonly chain: string | null
  readonly address: string | null
  readonly addressTag: string | null
}

/**
 * An on-chain transaction leg (the runtime `BlockchainLocation` class).
 *
 * OpenAPI splits this: a source is `TransferSourceBlockchainLocation` (chain
 * only) and a destination is `TransferDestinationBlockchainLocation` (chain +
 * address). The service does not: it copies the recorded
 * `chain`/`address`/`addressTag` onto **both** legs and omits whichever of
 * those is unset. So this SDK decodes one shape for both sides, with every
 * field optional, rather than requiring an address that a source leg — or an
 * on-chain leg whose metadata has not backfilled — will not have.
 *
 * `address`/`addressTag` are redacted the same way `Money.amount` is.
 */
export class TransactionBlockchainLocation {
  readonly kind = 'blockchain' as const
  readonly chain: string | null
  readonly #address: string | null
  readonly #addressTag: string | null

  /** @internal Constructed only by the SDK's response decoder. */
  constructor(fields: { chain: string | null; address: string | null; addressTag: string | null }) {
    this.chain = fields.chain
    this.#address = fields.address
    this.#addressTag = fields.addressTag
    Object.freeze(this)
  }

  get address(): string | null {
    return this.#address
  }

  get addressTag(): string | null {
    return this.#addressTag
  }

  toJSON(): TransactionBlockchainLocationRendering {
    return {
      kind: this.kind,
      chain: this.chain,
      address: this.#address === null ? null : REDACTED,
      addressTag: this.#addressTag === null ? null : REDACTED,
    }
  }

  toString(): string {
    return (
      `TransactionBlockchainLocation(kind=blockchain, chain=${this.chain}, ` +
      `address=${this.#address === null ? 'null' : REDACTED}, ` +
      `addressTag=${this.#addressTag === null ? 'null' : REDACTED})`
    )
  }
}

/**
 * A fiat transaction leg (OpenAPI `TransactionFiatLocation`). `wire` and `ach`
 * are the discriminator values, so they are `kind` rather than a nested type
 * field. `name` is the human-readable bank or rail label when available; it is
 * not redacted, matching `WithdrawalDestination.name`.
 */
export type TransactionFiatLocation = {
  readonly kind: 'wire' | 'ach'
  readonly fiatAccountId: string
  readonly name: string | null
}

/**
 * A transaction source or destination leg. The service uses one location type
 * on both sides; OpenAPI documents two `oneOf`s that this union
 * is the product of. A `verified_blockchain` leaking through, or a kind not
 * yet invented, degrades to `unrecognized`.
 */
export type TransactionLocation =
  | TransactionAccountLocation
  | TransactionBlockchainLocation
  | TransactionFiatLocation
  | { readonly kind: 'unrecognized'; readonly rawValue: string | null }

/** The redacted shape `JSON.stringify(transaction)` produces. */
export type TransactionRendering = {
  readonly id: string
  readonly type: TransactionType
  readonly status: TransactionStatus
  readonly amount: { readonly amount: string; readonly currency: string }
  readonly source: TransactionLocation | null
  readonly destination: TransactionLocation | null
  readonly createDate: string
  readonly updateDate: string
}

/**
 * A DAA unified activity row (OpenAPI `Transaction`), as
 * `GET /v1/accounts/transactions` reports it.
 *
 * There is no by-id read: the API is list-only for transactions.
 *
 * **Guaranteed fields** are `id`, `type`, `status`, `amount`, `createDate`, and
 * `updateDate`. Those six are marked required, and every service path that
 * produces a transaction always sets them. `source` and `destination` are
 * documented "when available", and the service omits an absent leg rather than
 * sending JSON `null`.
 *
 * **`amount` does not appear in any default rendering.** It sits behind a
 * prototype accessor, so `Object.keys`, `JSON.stringify`, spread, `for...in`,
 * and `console.log` do not reach it. A blockchain leg redacts its own address.
 *
 * Not constructible by a consumer: exported from `index.ts` as a type only,
 * and the `#amount` field makes the type nominal.
 */
export class Transaction {
  readonly id: string
  readonly type: TransactionType
  readonly status: TransactionStatus
  readonly source: TransactionLocation | null
  readonly destination: TransactionLocation | null
  readonly createDate: string
  readonly updateDate: string
  readonly #amount: Money

  /** @internal Constructed only by the SDK's response decoder. */
  constructor(fields: {
    readonly id: string
    readonly type: TransactionType
    readonly status: TransactionStatus
    readonly amount: Money
    readonly source: TransactionLocation | null
    readonly destination: TransactionLocation | null
    readonly createDate: string
    readonly updateDate: string
  }) {
    this.id = fields.id
    this.type = fields.type
    this.status = fields.status
    this.source = fields.source
    this.destination = fields.destination
    this.createDate = fields.createDate
    this.updateDate = fields.updateDate
    this.#amount = fields.amount
    Object.freeze(this)
  }

  get amount(): Money {
    return this.#amount
  }

  toJSON(): TransactionRendering {
    return {
      id: this.id,
      type: this.type,
      status: this.status,
      amount: this.#amount.toJSON(),
      source: this.source,
      destination: this.destination,
      createDate: this.createDate,
      updateDate: this.updateDate,
    }
  }

  toString(): string {
    return (
      `Transaction(id=${this.id}, type=${this.type.kind}, status=${this.status.kind}, ` +
      `amount=${this.#amount.toString()}, createDate=${this.createDate}, updateDate=${this.updateDate})`
    )
  }
}
