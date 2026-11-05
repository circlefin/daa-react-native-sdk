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

import {
  Fee,
  Transfer,
  TransferDestinationAccountLocation,
  TransferDestinationBlockchainLocation,
  TransferDestinationLocation,
  TransferErrorCode,
  TransferPolicyEvaluation,
  TransferSourceLocation,
  TransferStatus,
} from '../models/Transfer'
import { requiredMoney, toMoney } from './moneyPayload'
import {
  asObject,
  MalformedPayloadError,
  optionalObject,
  optionalString,
  requiredString,
  unrecognized,
} from './payload'

/**
 * Wire payload -> public `Transfer` model, and the required/optional line.
 *
 * Generic object and string readers come from `wire/payload`; shared money
 * decoding comes from `wire/moneyPayload`; transfer-specific fee, enum, and
 * location decoding remains here.
 */

// ---- Closed-set tables, one per field, mirroring wire/wireEnums.ts's pattern ----
//
// These tables remain resource-specific because their public unions do; they use
// the same `Map` construction as the account tables. An object literal inherits
// from `Object.prototype`, so
// `lookup['constructor']` returns a function instead of `undefined`, and a wire
// value spelled like a prototype member would be "recognised" as something it
// is not. Pinned by test, same as the account tables.

const TRANSFER_STATUSES = new Map<string, TransferStatus>([
  ['pending', Object.freeze({ kind: 'pending' })],
  ['complete', Object.freeze({ kind: 'complete' })],
  ['failed', Object.freeze({ kind: 'failed' })],
])

const TRANSFER_ERROR_CODES = new Map<string, TransferErrorCode>([
  ['transfer_failed', Object.freeze({ kind: 'transfer_failed' })],
  ['transfer_denied', Object.freeze({ kind: 'transfer_denied' })],
  ['blockchain_error', Object.freeze({ kind: 'blockchain_error' })],
  ['insufficient_funds', Object.freeze({ kind: 'insufficient_funds' })],
  ['invalid_crypto_address', Object.freeze({ kind: 'invalid_crypto_address' })],
])

function toTransferStatus(raw: string): TransferStatus {
  return TRANSFER_STATUSES.get(raw) ?? unrecognized(raw)
}

/** `errorCode` is optional (present only when `status = failed`); absent is `null`, not `unrecognized`. */
function toTransferErrorCode(raw: string | null): TransferErrorCode | null {
  if (raw === null) {
    return null
  }
  return TRANSFER_ERROR_CODES.get(raw) ?? unrecognized(raw)
}

// ---- Locations ----
//
// The discriminator is the wire `type` field shared by every location. A
// transfer leg is documented as only ever `account` or `blockchain` (`wire` is
// not valid on a transfer), but the decoder still has to tolerate anything
// else — a `verified_blockchain`/`wire`/`ach` leaking through, or a kind
// invented after this SDK shipped — as `unrecognized` rather than a thrown
// error.
//
// `chain` (both legs) and `address` (destination only) are read with
// `optionalString`, not `requiredString`, even though the OpenAPI schema marks
// both required. That marking is a hint, not proof: the service sends no
// `chain` on any blockchain leg whose metadata has not backfilled, and no
// `address` on a destination verified-blockchain leg in the same state (a plain
// destination `blockchain` leg falls back to the leg id, so it never actually
// sends a null address). Since the wire's `type: "blockchain"` cannot
// distinguish which kind of leg produced it, this decoder has to accept the
// nullable case both fields actually have.

function toTransferSourceLocation(value: unknown): TransferSourceLocation {
  const payload = asObject(value, 'source')
  const type = requiredString(payload, 'type', 'source.type')
  switch (type) {
    case 'account':
      return Object.freeze({
        kind: 'account' as const,
        accountId: requiredString(payload, 'id', 'source.id'),
      })
    case 'blockchain':
      return Object.freeze({
        kind: 'blockchain' as const,
        // See the note above `toTransferSourceLocation`: nullable, not required.
        chain: optionalString(payload, 'chain'),
      })
    default:
      return unrecognized(type)
  }
}

/**
 * `source` itself is optional on `Transfer` (see `models/Transfer.ts`'s class
 * note): a fiat leg or a stray `verified_blockchain` source both map to a
 * service-side `null`, which the service sends as an absent key rather than an
 * explicit JSON `null` — so both are treated as absence here,
 * consistent with every other optional field in this file.
 */
function toOptionalTransferSourceLocation(value: unknown): TransferSourceLocation | null {
  if (value === undefined || value === null) {
    return null
  }
  return toTransferSourceLocation(value)
}

function toTransferDestinationLocation(value: unknown): TransferDestinationLocation {
  const payload = asObject(value, 'destination')
  const type = requiredString(payload, 'type', 'destination.type')
  switch (type) {
    case 'account':
      return new TransferDestinationAccountLocation({
        accountId: requiredString(payload, 'id', 'destination.id'),
        address: optionalString(payload, 'address'),
        addressTag: optionalString(payload, 'addressTag'),
      })
    case 'blockchain':
      return new TransferDestinationBlockchainLocation({
        // See the note above `toTransferSourceLocation`: nullable, not required.
        chain: optionalString(payload, 'chain'),
        address: optionalString(payload, 'address'),
        addressTag: optionalString(payload, 'addressTag'),
      })
    default:
      return unrecognized(type)
  }
}

/** `destination` itself is optional on `Transfer` — see `toOptionalTransferSourceLocation`; same reasoning, a fiat destination leg. */
function toOptionalTransferDestinationLocation(value: unknown): TransferDestinationLocation | null {
  if (value === undefined || value === null) {
    return null
  }
  return toTransferDestinationLocation(value)
}

/**
 * A single fee entry. All three fields are guaranteed on a `Fee` that is
 * present at all (the OpenAPI schema marks `amount`/`currency`/`type` each
 * required) — it is the `fees` array itself that is
 * optional on `Transfer`, not any field within an entry that does appear.
 */
function toFee(value: unknown): Fee {
  const payload = asObject(value, 'fees[]')
  return Object.freeze({
    amount: toMoney(payload, 'fees[]'),
    type: requiredString(payload, 'type', 'fees[].type'),
  })
}

/**
 * `fees` is present only when at least one non-zero fee exists (per the API
 * contract); absent or `null` decodes to an empty list rather
 * than `null`, since "no fees" and "an empty fee list" are the same fact.
 */
function toFees(payload: Record<string, unknown>): Fee[] {
  const value = payload['fees']
  if (value === undefined || value === null) {
    return []
  }
  if (!Array.isArray(value)) {
    throw new MalformedPayloadError('fees')
  }
  return value.map(toFee)
}

function toPolicyEvaluation(payload: Record<string, unknown>): TransferPolicyEvaluation {
  return Object.freeze({ status: requiredString(payload, 'status', 'policyEvaluation.status') })
}

/**
 * Map a decoded `Transfer` payload onto the public model.
 *
 * Unknown *additional* fields are ignored and an unfamiliar *present*
 * closed-set or location value degrades to `unrecognized`; a missing guaranteed
 * field throws. **Guaranteed fields are only `id`, `amount`, and `status`** —
 * the OpenAPI schema's required marking is a hint, not proof (see
 * `models/Transfer.ts`'s file-level note), and `source`/`destination` both have
 * a real service code path to absent (a fiat leg), so they decode to `null`
 * rather than throwing when missing. `fees`, `transactionHash`, `errorCode`,
 * and `policyEvaluation` are documented as present only in some cases and
 * decode to empty/`null` when absent. `createDate` is not marked required at
 * all — the same kind of gap as `Account.description`, which the service can
 * omit — so it is treated as optional here rather than rejecting an
 * otherwise-readable transfer on a guess.
 *
 * `destinationTransactionHash` follows the same "present only when …" pattern
 * as `transactionHash`: it is the CCTP destination-mint hash, present only
 * once the destination leg of a cross-chain transfer has minted, and decodes
 * to `null` when absent.
 *
 * @throws MalformedPayloadError
 */
export function toTransfer(value: unknown): Transfer {
  const payload = asObject(value, 'transfer')

  return new Transfer({
    id: requiredString(payload, 'id'),
    source: toOptionalTransferSourceLocation(payload['source']),
    destination: toOptionalTransferDestinationLocation(payload['destination']),
    amount: requiredMoney(payload, 'amount'),
    fees: toFees(payload),
    transactionHash: optionalString(payload, 'transactionHash'),
    destinationTransactionHash: optionalString(payload, 'destinationTransactionHash'),
    status: toTransferStatus(requiredString(payload, 'status')),
    errorCode: toTransferErrorCode(optionalString(payload, 'errorCode')),
    policyEvaluation: (() => {
      const policyEvaluation = optionalObject(payload, 'policyEvaluation')
      return policyEvaluation === null ? null : toPolicyEvaluation(policyEvaluation)
    })(),
    createDate: optionalString(payload, 'createDate'),
  })
}

export function toTransfers(value: unknown): readonly Transfer[] {
  if (!Array.isArray(value)) {
    throw new MalformedPayloadError('transfers')
  }
  return Object.freeze(value.map(toTransfer))
}
