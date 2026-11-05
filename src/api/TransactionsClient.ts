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

import { contractViolation } from '../errors'
import type { Page } from '../models/Page'
import type { Transaction } from '../models/Transaction'
import type { DaaTransport } from '../transport/DaaTransport'
import { toTransactions } from '../wire/transactionPayload'
import { readPage } from './pagination'
import { append, appendEnum, appendEnums, appendString, appendUuid } from './queryParameters'

/**
 * `GET /v1/accounts/transactions` — the **public** path, exactly as for
 * transfers.
 */
const TRANSACTION_COLLECTION_PATH = '/v1/accounts/transactions'

const TRANSACTION_TYPES = Object.freeze([
  'deposit',
  'withdrawal',
  'transfer',
  'fx',
  'fee',
  'credit',
  'other',
] as const)

const TRANSACTION_STATUSES = Object.freeze(['pending', 'complete', 'failed', 'returned'] as const)

export type TransactionListQuery = Readonly<{
  /** Select a backing source explicitly; omitted derives from `accountId` or defaults to omnibus. */
  custodyType?: 'omnibus' | 'segregated' | 'self'
  /** Match activity for this public account id. */
  accountId?: string
  /** Match activity for one end-user sub-entity. */
  clientEntityId?: string
  isAttributed?: boolean
  type?: readonly (typeof TRANSACTION_TYPES)[number][]
  status?: readonly (typeof TRANSACTION_STATUSES)[number][]
  /** ISO 4217 / crypto currency code; not constrained to a known set. */
  currency?: string
  /** Inclusive RFC 3339 creation-time lower bound. */
  from?: string
  /** Inclusive RFC 3339 creation-time upper bound. */
  to?: string
  /** Initial forward keyset cursor. Link-derived navigation remains opaque. */
  pageAfter?: string
  /** Initial backward keyset cursor. Link-derived navigation remains opaque. */
  pageBefore?: string
  pageSize?: number
}>

/**
 * Reads over DAA unified account activity, as the SDK contract's
 * `TransactionsClient`.
 *
 * Only {@link list} exists. There is no by-id read: the API has none, and
 * this client does not invent a `GET .../{id}`. Listing is an **ordinary typed read
 * with no device signature**. {@link list} retains the API's RFC 8288
 * navigation queries as opaque text.
 *
 * Not constructible by a consumer: exported from `index.ts` as a type only,
 * and the `#transport` field makes the type nominal.
 */
export class TransactionsClient {
  readonly #transport: DaaTransport
  readonly #publicApiOrigin: string

  /** @internal Constructed only through the internal user-client factory. */
  constructor(transport: DaaTransport, publicApiOrigin: string) {
    this.#transport = transport
    this.#publicApiOrigin = publicApiOrigin
    Object.freeze(this)
  }

  /** List transactions and retain the API's opaque navigation queries unchanged. */
  async list(query?: TransactionListQuery): Promise<Page<Transaction>> {
    return readPage({
      transport: this.#transport,
      publicApiOrigin: this.#publicApiOrigin,
      path: TRANSACTION_COLLECTION_PATH,
      query: transactionListQuery(query),
      decode: toTransactions,
    })
  }
}

function transactionListQuery(query: TransactionListQuery | undefined): string | null {
  if (query === undefined) return null
  if (typeof query !== 'object' || query === null || Array.isArray(query)) {
    throw contractViolation('transaction list query must be an object')
  }
  if (query.pageAfter !== undefined && query.pageBefore !== undefined) {
    throw contractViolation('pageAfter and pageBefore cannot be used together')
  }

  const parts: string[] = []
  appendEnum(parts, 'custodyType', query.custodyType, ['omnibus', 'segregated', 'self'])
  appendString(parts, 'accountId', query.accountId)
  appendUuid(parts, 'clientEntityId', query.clientEntityId)
  if (query.isAttributed !== undefined) {
    if (typeof query.isAttributed !== 'boolean') {
      throw contractViolation('isAttributed must be a boolean')
    }
    append(parts, 'isAttributed', String(query.isAttributed))
  }
  appendEnums(parts, 'type', query.type, TRANSACTION_TYPES)
  appendEnums(parts, 'status', query.status, TRANSACTION_STATUSES)
  appendString(parts, 'currency', query.currency)
  appendString(parts, 'from', query.from)
  appendString(parts, 'to', query.to)
  // The service models transaction cursors as UUID transaction ids.
  appendUuid(parts, 'pageAfter', query.pageAfter)
  appendUuid(parts, 'pageBefore', query.pageBefore)
  if (query.pageSize !== undefined) {
    if (!Number.isInteger(query.pageSize) || query.pageSize < 1) {
      throw contractViolation('pageSize must be a positive integer')
    }
    append(parts, 'pageSize', String(query.pageSize))
  }
  return parts.length === 0 ? null : parts.join('&')
}
