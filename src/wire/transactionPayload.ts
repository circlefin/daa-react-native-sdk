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
  Transaction,
  TransactionBlockchainLocation,
  TransactionLocation,
  TransactionStatus,
  TransactionType,
} from '../models/Transaction'
import { requiredMoney } from './moneyPayload'
import {
  asObject,
  MalformedPayloadError,
  optionalString,
  requiredString,
  unrecognized,
} from './payload'

/**
 * Wire payload -> public `Transaction` model, and the required/optional line.
 *
 * Generic object and string readers come from `wire/payload`; shared money
 * decoding comes from `wire/moneyPayload`. Transaction-specific enum and
 * location decoding remains here.
 */

const TRANSACTION_TYPES = new Map<string, TransactionType>([
  ['deposit', Object.freeze({ kind: 'deposit' })],
  ['withdrawal', Object.freeze({ kind: 'withdrawal' })],
  ['transfer', Object.freeze({ kind: 'transfer' })],
  ['fx', Object.freeze({ kind: 'fx' })],
  ['fee', Object.freeze({ kind: 'fee' })],
  ['credit', Object.freeze({ kind: 'credit' })],
  ['other', Object.freeze({ kind: 'other' })],
])

const TRANSACTION_STATUSES = new Map<string, TransactionStatus>([
  ['pending', Object.freeze({ kind: 'pending' })],
  ['complete', Object.freeze({ kind: 'complete' })],
  ['failed', Object.freeze({ kind: 'failed' })],
  ['returned', Object.freeze({ kind: 'returned' })],
])

function toTransactionType(raw: string): TransactionType {
  return TRANSACTION_TYPES.get(raw) ?? unrecognized(raw)
}

function toTransactionStatus(raw: string): TransactionStatus {
  return TRANSACTION_STATUSES.get(raw) ?? unrecognized(raw)
}

/**
 * Decode one `Location` hierarchy member.
 *
 * The discriminator is the wire `type` field. `account` and `blockchain` are shared with `Transfer`;
 * `wire`/`ach` are transaction-only. Anything else — including
 * `verified_blockchain`, which the service maps away before serializing — is
 * `unrecognized` rather than a thrown error.
 *
 * Fiat `id` is a UUID on the service; it is still read as a string here,
 * the same way every other response id is. Requiring UUID form on the way in
 * would reject a row the service actually sent.
 */
function toTransactionLocation(value: unknown, field: string): TransactionLocation {
  const payload = asObject(value, field)
  const type = requiredString(payload, 'type', `${field}.type`)
  switch (type) {
    case 'account':
      return Object.freeze({
        kind: 'account' as const,
        accountId: requiredString(payload, 'id', `${field}.id`),
      })
    case 'blockchain':
      return new TransactionBlockchainLocation({
        chain: optionalString(payload, 'chain'),
        address: optionalString(payload, 'address'),
        addressTag: optionalString(payload, 'addressTag'),
      })
    case 'wire':
    case 'ach':
      return Object.freeze({
        kind: type,
        fiatAccountId: requiredString(payload, 'id', `${field}.id`),
        name: optionalString(payload, 'name'),
      })
    default:
      return unrecognized(type)
  }
}

function toOptionalTransactionLocation(value: unknown, field: string): TransactionLocation | null {
  if (value === undefined || value === null) {
    return null
  }
  return toTransactionLocation(value, field)
}

/**
 * Map a decoded `Transaction` payload onto the public model.
 *
 * Unknown additional fields are ignored and an unfamiliar present closed-set
 * or location value degrades to `unrecognized`; a missing guaranteed field
 * throws. Guaranteed fields are `id`, `type`, `status`, `amount`, `createDate`,
 * and `updateDate` — see `models/Transaction.ts`. `source` and `destination`
 * decode to `null` when absent.
 *
 * @throws MalformedPayloadError
 */
export function toTransaction(value: unknown): Transaction {
  const payload = asObject(value, 'transaction')

  return new Transaction({
    id: requiredString(payload, 'id'),
    type: toTransactionType(requiredString(payload, 'type')),
    status: toTransactionStatus(requiredString(payload, 'status')),
    amount: requiredMoney(payload, 'amount'),
    source: toOptionalTransactionLocation(payload['source'], 'source'),
    destination: toOptionalTransactionLocation(payload['destination'], 'destination'),
    createDate: requiredString(payload, 'createDate'),
    updateDate: requiredString(payload, 'updateDate'),
  })
}

export function toTransactions(value: unknown): readonly Transaction[] {
  if (!Array.isArray(value)) {
    throw new MalformedPayloadError('transactions')
  }
  return Object.freeze(value.map(toTransaction))
}
