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

// A DAA transfer's closed-set fields and its polymorphic source/destination legs.
//
// Same posture as `Account`'s closed-set fields (see `models/Account.ts`): a
// discriminated union on `kind` rather than a string-literal union, because a
// string-literal union has no room for a value the service adds later — decoding
// into one would either throw (making the whole transfer unreadable because one
// status or location kind was unfamiliar) or silently widen to `string`, which
// throws away the closed set the type exists to express. An unfamiliar *present*
// value degrades to `unrecognized`, carrying the raw string so a caller — or
// support, reading a bug report — can answer "why did this read as unknown"
// rather than just "it did".
//
// **A general note on how requiredness is decided in this file**: a response
// field marked required in the service's OpenAPI schema is a hint that it is
// *usually* present — never proof. The only evidence that settles it is whether
// a code path in the service can produce the value absent. The service's
// mapping of transfer legs is that evidence for `source`, `destination`, and
// the blockchain leg's `chain`/`address` — each is marked required and each has
// a real path to `null`, documented per-field below. Treating them as required
// would reject perfectly ordinary transfers (a fiat onramp/offramp leg, or a
// blockchain leg recorded before its chain/address metadata backfilled) — the
// same class of defect `Account.description` shows.

/**
 * Where a transfer is in its lifecycle (OpenAPI `TransferStatus`, wire values
 * are the enum constant names verbatim).
 *
 * `pending` also covers any asynchronous processing before settlement: the
 * public contract has no intermediate state, so that phase folds into
 * `pending` before this SDK ever sees it.
 */
export type TransferStatus =
  | { readonly kind: 'pending' }
  /** Terminal: successfully settled. */
  | { readonly kind: 'complete' }
  /** Terminal: failed or denied — see {@link TransferErrorCode}. */
  | { readonly kind: 'failed' }
  | { readonly kind: 'unrecognized'; readonly rawValue: string | null }

/**
 * Why a transfer failed (OpenAPI `TransferErrorCode`), present only when
 * {@link TransferStatus} is `failed`.
 *
 * This is the service's own public subset: internal failure reasons fold into
 * `transfer_failed` before they reach the wire.
 * Still modeled as an open set here rather than trusted to stay exactly five
 * values — the public enum can grow without this SDK's say-so, and a value it has
 * not shipped for must read as `unrecognized`, not fail the transfer.
 */
export type TransferErrorCode =
  | { readonly kind: 'transfer_failed' }
  | { readonly kind: 'transfer_denied' }
  | { readonly kind: 'blockchain_error' }
  | { readonly kind: 'insufficient_funds' }
  | { readonly kind: 'invalid_crypto_address' }
  | { readonly kind: 'unrecognized'; readonly rawValue: string | null }

/**
 * A transfer's source leg (OpenAPI `TransferSourceLocation`, a `oneOf` of
 * `TransferSourceAccountLocation` and `TransferSourceBlockchainLocation`).
 *
 * Neither source shape ever carries an address: `TransferSourceAccountLocation`
 * has only `id`, and `TransferSourceBlockchainLocation` has only `chain` — a
 * transfer's origin address is not part of the public contract. Both are safe as
 * plain frozen literals, unlike the destination union below, because neither
 * carries a value this SDK must redact.
 *
 * The wire discriminator is the location's shared `type` property, keyed here
 * to `account` / `blockchain` — the only two location types the contract
 * allows for a transfer leg (`verified_blockchain`, `wire`, and `ach` are
 * `Transaction`-only). A transfer that ever carries one of those, or a location
 * kind not yet invented, degrades to `unrecognized` with the raw `type` string
 * rather than failing the whole read — the same forward-compatibility contract as
 * every other closed set here.
 */
export type TransferSourceLocation =
  | {
      readonly kind: 'account'
      /** The account id. Named `accountId` here (the wire spells it `id`) so it
       * is not confused with the transfer's own `id` at `transfer.source.id`. */
      readonly accountId: string
    }
  | {
      readonly kind: 'blockchain'
      /**
       * Chain of the on-chain leg, as a plain string rather than a closed set —
       * same reasoning as `Account.blockchain`: new chains ship without an SDK
       * release, and the service's own chain type is the thing that would have
       * to grow, not this union.
       *
       * **Nullable**, despite the OpenAPI schema marking
       * `TransferSourceBlockchainLocation.chain` required: the service builds a
       * blockchain source leg with no chain when the leg was recorded before its
       * blockchain metadata backfilled, and the schema does not prevent it from
       * sending that leg anyway.
       */
      readonly chain: string | null
    }
  | { readonly kind: 'unrecognized'; readonly rawValue: string | null }

/** The redacted shape `JSON.stringify`/`toString` produce for a destination account leg. */
export type TransferDestinationAccountLocationRendering = {
  readonly kind: 'account'
  readonly accountId: string
  readonly address: string | null
  readonly addressTag: string | null
}

/**
 * A transfer destination that is a DAA account (OpenAPI
 * `TransferDestinationAccountLocation`).
 *
 * Unlike the source shape, a destination account leg can carry the on-chain
 * `address`/`addressTag` funds arrived at — present only when this account leg
 * received a crypto deposit. A crypto address is treated as sensitive data, so
 * it is held the same way `Money` holds `amount`: behind a `#` private field
 * and a prototype accessor, with `toJSON`/`toString` reporting only *whether*
 * one is present. The service redacts it from its own logs but still sends it
 * in the JSON body; this SDK redacts the JSON rendering too.
 */
export class TransferDestinationAccountLocation {
  readonly kind = 'account' as const
  readonly accountId: string
  readonly #address: string | null
  readonly #addressTag: string | null

  /** @internal Constructed only by the SDK's response decoder. */
  constructor(fields: { accountId: string; address: string | null; addressTag: string | null }) {
    this.accountId = fields.accountId
    this.#address = fields.address
    this.#addressTag = fields.addressTag
    Object.freeze(this)
  }

  /** The on-chain address this account leg received a deposit at, or `null` if it did not. */
  get address(): string | null {
    return this.#address
  }

  /** Secondary on-chain identifier (e.g. a Stellar memo) paired with {@link address}; nullable. */
  get addressTag(): string | null {
    return this.#addressTag
  }

  toJSON(): TransferDestinationAccountLocationRendering {
    return {
      kind: this.kind,
      accountId: this.accountId,
      address: this.#address === null ? null : REDACTED,
      addressTag: this.#addressTag === null ? null : REDACTED,
    }
  }

  toString(): string {
    return (
      `TransferDestinationAccountLocation(kind=account, accountId=${this.accountId}, ` +
      `address=${this.#address === null ? 'null' : REDACTED}, ` +
      `addressTag=${this.#addressTag === null ? 'null' : REDACTED})`
    )
  }
}

/** The redacted shape `JSON.stringify`/`toString` produce for a destination blockchain leg. */
export type TransferDestinationBlockchainLocationRendering = {
  readonly kind: 'blockchain'
  readonly chain: string | null
  readonly address: string | null
  readonly addressTag: string | null
}

/**
 * A transfer destination that is an on-chain address (OpenAPI
 * `TransferDestinationBlockchainLocation`).
 *
 * **Both `chain` and `address` are nullable here, despite the OpenAPI schema
 * marking both required.** The wire's `type: "blockchain"` comes from two
 * different kinds of leg that this SDK cannot tell apart from the JSON alone:
 * a verified-blockchain leg folds into it, because the public transfer
 * taxonomy has no verified form on a read.
 *
 * - A plain blockchain leg always resolves `address` (the service falls back
 *   to the stored leg id when metadata is absent), so that path alone would
 *   justify treating it as required.
 * - A folded verified-blockchain leg does **not** fall back — one with no
 *   recorded metadata yet genuinely has no address to report.
 * - Both kinds report `chain` only once their blockchain metadata is
 *   recorded.
 *
 * Since either path can produce the wire shape this SDK decodes, and one of
 * them can leave `address` absent, `address` has to be modeled as optional —
 * requiring it would reject a real, un-backfilled verified-blockchain
 * destination. Both fields are redacted the same way `Money.amount` is: behind
 * a `#` private field, never an own enumerable property; `chain` is public
 * because it is not sensitive.
 */
export class TransferDestinationBlockchainLocation {
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

  /** The destination on-chain address, or `null` for an un-backfilled verified-blockchain leg. See the class note. */
  get address(): string | null {
    return this.#address
  }

  /** Secondary on-chain identifier (e.g. a Stellar memo) paired with {@link address}; nullable. */
  get addressTag(): string | null {
    return this.#addressTag
  }

  toJSON(): TransferDestinationBlockchainLocationRendering {
    return {
      kind: this.kind,
      chain: this.chain,
      address: this.#address === null ? null : REDACTED,
      addressTag: this.#addressTag === null ? null : REDACTED,
    }
  }

  toString(): string {
    return (
      `TransferDestinationBlockchainLocation(kind=blockchain, chain=${this.chain}, ` +
      `address=${this.#address === null ? 'null' : REDACTED}, ` +
      `addressTag=${this.#addressTag === null ? 'null' : REDACTED})`
    )
  }
}

/**
 * A transfer's destination leg (OpenAPI `TransferDestinationLocation`, a `oneOf`
 * of `TransferDestinationBlockchainLocation` and `TransferDestinationAccountLocation`).
 *
 * See {@link TransferSourceLocation} for the shared discriminator and the
 * forward-compatibility contract for a `type` this SDK does not recognise.
 */
export type TransferDestinationLocation =
  | TransferDestinationAccountLocation
  | TransferDestinationBlockchainLocation
  | { readonly kind: 'unrecognized'; readonly rawValue: string | null }

/**
 * A single fee applied to a transfer (OpenAPI `Fee`).
 *
 * `amount` reuses `Money` rather than carrying its own decimal string — the exact
 * problem `Money` already solves (the service serializes `Fee.amount` the same
 * way, as a plain decimal string) and redacts the same way. `type` is a plain
 * `string`: the service does not constrain it to an enum (the schema's
 * `network` value is documentation only, not a runtime constraint), so there is
 * no closed set to model or to get wrong.
 */
export type Fee = {
  readonly amount: Money
  readonly type: string
}

/**
 * Policy-engine evaluation attached to a transfer when one is available (OpenAPI
 * `PolicyEvaluation`).
 *
 * `status` is a plain `string`, matching the service: `PolicyEvaluation.status`
 * is a free-form string, not an enum, so — unlike `TransferStatus`/
 * `TransferErrorCode` — there is no closed set to widen or to fall back from.
 */
export type TransferPolicyEvaluation = {
  readonly status: string
}

/** The redacted shape `JSON.stringify(transfer)` produces. */
export type TransferRendering = {
  readonly id: string
  readonly source: TransferSourceLocation | null
  readonly destination: TransferDestinationLocation | null
  readonly amount: { readonly amount: string; readonly currency: string }
  readonly fees: string
  readonly transactionHash: string | null
  readonly destinationTransactionHash: string | null
  readonly status: TransferStatus
  readonly errorCode: TransferErrorCode | null
  readonly policyEvaluation: TransferPolicyEvaluation | null
  readonly createDate: string | null
}

/**
 * A DAA transfer, as the service reports it (OpenAPI `Transfer`, the response
 * contract for `POST /v1/accounts/transfers`, each element of
 * `GET /v1/accounts/transfers`, and `GET /v1/accounts/transfers/{transferId}`).
 *
 * Read-only at runtime as well as in the type system, for the same reason as
 * `Account`: `readonly` is erased at compile time and would leave a returned
 * transfer mutable through a cast. The instance is frozen and the fee list is a
 * frozen array.
 *
 * **Not constructible by a consumer.** Exported from `index.ts` as a type only,
 * and the `#` private fields make the type nominal so an object literal cannot
 * be typed as a `Transfer`.
 *
 * **Only `id`, `amount`, and `status` are guaranteed non-null here — `source`
 * and `destination` are not, despite the OpenAPI schema marking all five
 * required.** That marking is a hint, not proof; the only evidence that
 * settles requiredness is whether a service code path can produce the value
 * absent, and for `source`/`destination` one does: the service reports no leg
 * at all for a fiat source or destination, and no source leg for a
 * verified-blockchain source. A transfer with a fiat leg — an ordinary onramp
 * or offramp — is real, and the service omits null locations, so that leg is
 * simply **absent** from the JSON body, not `null`; requiring it would reject
 * an otherwise-readable transfer. `fees`, `transactionHash`,
 * `destinationTransactionHash`, `errorCode`, and `policyEvaluation` are each
 * documented as present only in some cases (a non-zero fee exists; a leg is
 * blockchain; the CCTP destination leg has minted; status is `failed`; one is
 * available) and decode to empty/`null` when absent, exactly as documented.
 *
 * **`createDate` is treated as optional despite looking mandatory**, and that is
 * a deliberate hedge rather than an oversight: the OpenAPI schema does not mark
 * it required at all (unlike `id`/`amount`/`status`) — the same kind of gap
 * as `Account.description`, which the service can omit. This SDK reports it
 * as it finds it rather than rejecting a transfer that is otherwise perfectly
 * readable.
 *
 * **`amount` and `fees` do not appear in any default rendering.** Like `Account`'s
 * `balances`, they sit behind prototype accessors rather than own properties, so
 * `Object.keys`, `JSON.stringify`, `{ ...transfer }`, `for...in`, and the object
 * inspectors behind `console.log` do not reach them; `toJSON`/`toString` reduce
 * `fees` to a count and delegate `amount` to `Money`'s own redacted rendering.
 * `source`/`destination` are plain own properties — safe, because a location that
 * can carry an address redacts it itself (see
 * {@link TransferDestinationAccountLocation}/{@link TransferDestinationBlockchainLocation}).
 */
export class Transfer {
  /** Transfer id. */
  readonly id: string

  /** `null` for a fiat leg (an onramp) or a stray `verified_blockchain` source — see the class note. */
  readonly source: TransferSourceLocation | null

  /** `null` for a fiat leg (an offramp) — see the class note. */
  readonly destination: TransferDestinationLocation | null

  readonly status: TransferStatus

  /** Present only when {@link status} is `failed`. */
  readonly errorCode: TransferErrorCode | null

  /** On-chain transaction hash; present only when a leg is blockchain. */
  readonly transactionHash: string | null

  /**
   * CCTP destination-mint hash — the transaction hash of the destination leg
   * minting on the receiving chain. Present only for a CCTP transfer once
   * that leg has minted; `null` otherwise.
   */
  readonly destinationTransactionHash: string | null

  /** Policy-evaluation; absent until one is available. */
  readonly policyEvaluation: TransferPolicyEvaluation | null

  /** Creation timestamp, exactly as the service sent it (ISO-8601 UTC). See the class note on why this is optional. */
  readonly createDate: string | null

  readonly #amount: Money
  readonly #fees: readonly Fee[]

  /** @internal Constructed only by the SDK's response decoder. */
  constructor(fields: {
    readonly id: string
    readonly source: TransferSourceLocation | null
    readonly destination: TransferDestinationLocation | null
    readonly amount: Money
    readonly fees: readonly Fee[]
    readonly transactionHash: string | null
    readonly destinationTransactionHash: string | null
    readonly status: TransferStatus
    readonly errorCode: TransferErrorCode | null
    readonly policyEvaluation: TransferPolicyEvaluation | null
    readonly createDate: string | null
  }) {
    this.id = fields.id
    this.source = fields.source
    this.destination = fields.destination
    this.status = fields.status
    this.errorCode = fields.errorCode
    this.transactionHash = fields.transactionHash
    this.destinationTransactionHash = fields.destinationTransactionHash
    this.policyEvaluation = fields.policyEvaluation
    this.createDate = fields.createDate
    this.#amount = fields.amount
    // Same reasoning as `Account#balances`: freezing a copy rather than the
    // caller's own array, so this construction cannot reach back and freeze an
    // argument the caller still holds a reference to.
    this.#fees = Object.freeze(fields.fees.slice())
    Object.freeze(this)
  }

  /** The transferred amount. Reuses `Money`, which redacts its own `amount` field. */
  get amount(): Money {
    return this.#amount
  }

  /** Applied fees. Empty when the service sent none (no non-zero fee exists). */
  get fees(): readonly Fee[] {
    return this.#fees
  }

  /** Identifiers and states render; the amount and fee amounts do not. */
  toJSON(): TransferRendering {
    return {
      id: this.id,
      source: this.source,
      destination: this.destination,
      amount: this.#amount.toJSON(),
      fees: `${this.#fees.length} entries`,
      transactionHash: this.transactionHash,
      destinationTransactionHash: this.destinationTransactionHash,
      status: this.status,
      errorCode: this.errorCode,
      policyEvaluation: this.policyEvaluation,
      createDate: this.createDate,
    }
  }

  /** Identifiers and states print; the amount and fee amounts do not. */
  toString(): string {
    return (
      `Transfer(id=${this.id}, status=${this.status.kind}, ` +
      `errorCode=${this.errorCode === null ? 'null' : this.errorCode.kind}, ` +
      `amount=${this.#amount.toString()}, fees=${this.#fees.length} entries, ` +
      `transactionHash=${this.transactionHash}, createDate=${this.createDate})`
    )
  }
}
