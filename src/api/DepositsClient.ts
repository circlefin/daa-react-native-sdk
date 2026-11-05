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
import type { Deposit } from '../models/Deposit'
import type { DepositSummary } from '../models/DepositSummary'
import type { Page } from '../models/Page'
import type { DaaTransport } from '../transport/DaaTransport'
import { isUuid } from '../validation/uuid'
import { toDeposit, toDepositSummaries } from '../wire/depositPayload'
import { readPage } from './pagination'
import { appendEnum, appendEnums, appendString, appendUuid } from './queryParameters'
import { readResource } from './resourceRequest'

/*
 * A deposit id is a UUID, and is checked as one rather than as a generic path
 * segment.
 *
 * The SDK contract types this parameter `depositId: UUID`, and the service
 * agrees, typing it as a required UUID. That is deliberately unlike
 * `AccountsClient`, whose signature is `accountId: string`, because public
 * account ids are strings, including numeric IDs. So the two guards differ on
 * purpose; applying one rule to both would make one of them wrong.
 *
 * A UUID-formatted identifier also contains none of the characters — `/`, `%`,
 * `.`, control bytes — that could redirect the request into a sibling route, so
 * this subsumes the path-segment check rather than merely differing from it.
 */
/**
 * `GET /v1/accounts/deposits/{id}` — the **public** path, which is what a
 * consumer's transport is handed, exactly as for `AccountsClient`.
 */
const DEPOSIT_PATH_PREFIX = '/v1/accounts/deposits/'
const DEPOSIT_COLLECTION_PATH = '/v1/accounts/deposits'

/**
 * The wire values of `DepositType` (`models/Deposit.ts`), in the order that
 * model declares them. Kept local to this query builder rather than exported
 * off the model — `AccountsClient`'s and `TransfersClient`'s query builders do
 * the same for their own filters — because the set a filter accepts is a
 * query-parameter concern, not something a decoded response needs to expose.
 *
 * This is **not** a runtime allowlist, despite the server's own `DepositType`
 * being a closed set. Deposit rails are a server-owned, externally-growing
 * catalog — each entry is a distinct banking network Circle integrates with —
 * and a new rail can arrive with no advance notice. `type` is used only as a
 * passthrough query filter — this SDK does no per-rail branching — so a locally
 * rejected filter value costs the caller a legitimate query with no
 * compensating safety benefit; the server remains the authority and 400s on a
 * genuinely unsupported value. Kept as a `const` union for editor autocomplete/typo
 * protection only, and exported so a test can pin it against the server's
 * `DepositType` wire values without duplicating the list.
 */
export const DEPOSIT_TYPES = Object.freeze([
  'wire',
  'ach',
  'cbit',
  'rtgs',
  'rtp',
  'xpay',
  'signet',
  'sepa',
  'sepa_instant',
  'sen',
  'pix',
  'cubix',
  'book_transfer',
  'fed_now',
] as const)

const DEPOSIT_STATUSES = Object.freeze(['pending', 'complete', 'failed'] as const)

/**
 * Filters and keyset pagination accepted by the deposit collection.
 *
 * Mirrors the service's deposit-list query parameters exactly:
 * `custodyType` is derived from `accountId` when omitted and otherwise
 * defaults to omnibus; `type` is a single filter, not repeatable, unlike
 * `status`, which the service accepts as a repeated parameter;
 * `pageAfter`/`pageBefore` are deposit ids, so — like `TransfersClient`'s
 * cursors and unlike `AccountsClient`'s opaque string ones — they are held to
 * `appendUuid` on the initial call. A `Link`-derived navigation query is never
 * parsed or rebuilt from this type; see `api/pagination.ts`.
 */
export type DepositListQuery = Readonly<{
  custodyType?: 'omnibus' | 'segregated' | 'self'
  accountId?: string
  type?: (typeof DEPOSIT_TYPES)[number]
  status?: readonly (typeof DEPOSIT_STATUSES)[number][]
  /** Inclusive RFC 3339 creation-time lower bound. */
  from?: string
  /** Inclusive RFC 3339 creation-time upper bound. */
  to?: string
  /** Initial forward keyset cursor (a deposit id). Link-derived navigation remains opaque. */
  pageAfter?: string
  /** Initial backward keyset cursor (a deposit id). Link-derived navigation remains opaque. */
  pageBefore?: string
  pageSize?: number
}>

/**
 * Reads over DAA deposits, as the SDK contract's `DepositsClient`
 * (`list(query?: DepositListQuery): Promise<Page<DepositSummary>>`,
 * `get(depositId: UUID): Promise<Deposit>`).
 *
 * {@link list} returns the compact `DepositSummary` projection the collection
 * endpoint actually serves — see `models/DepositSummary.ts`'s class note for
 * why that is a distinct type rather than `Deposit` with fields left
 * `undefined` — and retains the API's opaque navigation queries unchanged, the
 * same contract `TransfersClient.list` and `AccountsClient.list` honor.
 * {@link get} reads the full detail projection. Both are **ordinary typed
 * reads**: like `AccountsClient.get`, they need no device signature. Reached
 * through `DaaClient.forUser`.
 *
 * Not constructible by a consumer: exported from `index.ts` as a type only, and
 * the `#transport` field makes the type nominal.
 */
export class DepositsClient {
  readonly #transport: DaaTransport
  readonly #publicApiOrigin: string

  /** @internal Constructed only through `createDaaUserClient`. */
  constructor(transport: DaaTransport, publicApiOrigin: string) {
    this.#transport = transport
    this.#publicApiOrigin = publicApiOrigin
    Object.freeze(this)
  }

  /** List compact deposits and retain the API's opaque navigation queries unchanged. */
  async list(query?: DepositListQuery): Promise<Page<DepositSummary>> {
    return readPage({
      transport: this.#transport,
      publicApiOrigin: this.#publicApiOrigin,
      path: DEPOSIT_COLLECTION_PATH,
      query: depositListQuery(query),
      decode: toDepositSummaries,
    })
  }

  /**
   * Read one deposit.
   *
   * @param depositId The service-assigned identifier, a UUID. Anything else is
   *   rejected locally rather than sent: it cannot resolve to a deposit on the
   *   service side, so the round trip would only turn a caller's mistake into a
   *   `400`.
   * @throws DaaError with `detail.kind === 'contract_violation'` for a rejected
   *   `depositId` or a response the SDK cannot read, and `detail.kind === 'api'`
   *   for a status other than the documented `200`; `detail.kind === 'transport'`
   *   if the consumer's transport throws, with the thrown value as `err.cause`.
   */
  async get(depositId: string): Promise<Deposit> {
    if (!isUuid(depositId)) {
      throw contractViolation('depositId must be a UUID')
    }

    return readResource({
      transport: this.#transport,
      path: DEPOSIT_PATH_PREFIX + depositId,
      decode: toDeposit,
    })
  }
}

function depositListQuery(query: DepositListQuery | undefined): string | null {
  if (query === undefined) return null
  if (typeof query !== 'object' || query === null || Array.isArray(query)) {
    throw contractViolation('deposit list query must be an object')
  }
  if (query.pageAfter !== undefined && query.pageBefore !== undefined) {
    throw contractViolation('pageAfter and pageBefore cannot be used together')
  }

  const parts: string[] = []
  appendEnum(parts, 'custodyType', query.custodyType, ['omnibus', 'segregated', 'self'])
  appendString(parts, 'accountId', query.accountId)
  // `type` is a growable rail catalog, not a closed business vocabulary — see
  // `DEPOSIT_TYPES`'s doc above — so it is checked structurally, not against
  // the hardcoded set.
  appendString(parts, 'type', query.type)
  appendEnums(parts, 'status', query.status, DEPOSIT_STATUSES)
  appendString(parts, 'from', query.from)
  appendString(parts, 'to', query.to)
  appendUuid(parts, 'pageAfter', query.pageAfter)
  appendUuid(parts, 'pageBefore', query.pageBefore)
  if (query.pageSize !== undefined) {
    if (!Number.isInteger(query.pageSize) || query.pageSize < 1) {
      throw contractViolation('pageSize must be a positive integer')
    }
    appendString(parts, 'pageSize', String(query.pageSize))
  }
  return parts.length === 0 ? null : parts.join('&')
}
