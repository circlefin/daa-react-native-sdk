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
import type { AccountLimitsUsage } from '../models/AccountLimitsUsage'
import type { DaaTransport } from '../transport/DaaTransport'
import { toAccountLimitsUsage } from '../wire/accountLimitsUsagePayload'
import { appendEnum } from './queryParameters'
import { readResource } from './resourceRequest'

/**
 * `GET /v1/accounts/{accountId}/limits/usage` — the public path documented at
 * https://developers.circle.com/api-reference/digital-asset-accounts/all/list-account-limits-usage.
 *
 * The public API reference above is this client's contract.
 */
const ACCOUNT_LIMITS_USAGE_PATH_PREFIX = '/v1/accounts/'
const ACCOUNT_LIMITS_USAGE_PATH_SUFFIX = '/limits/usage'

/**
 * The public reference's documented pattern for this path parameter:
 * `^\d{1,10}$`. This is stricter than `AccountsClient.get`'s `accountId`
 * guard: account ids are strings in general, but this endpoint's reference
 * constrains the parameter to a numeric shape, so the guard follows the
 * documented contract for *this* endpoint. The same reasoning distinguishes `DepositsClient.get`'s UUID
 * guard from `AccountsClient.get`'s path-segment one.
 */
const ACCOUNT_ID_PATTERN = /^\d{1,10}$/

const OPERATIONS = Object.freeze([
  'deposit',
  'withdrawal',
  'receive',
  'send',
  'send_count',
  'address_linking',
  'fiat_linking',
  'deposit_return_count',
  'balance_cap',
] as const)

const ASSET_TYPES = Object.freeze(['fiat', 'crypto'] as const)

const WINDOWS = Object.freeze(['PT24H', 'P30D'] as const)

/** Filters accepted by the account limits/usage read, all optional. */
export type AccountLimitsUsageQuery = Readonly<{
  operation?: (typeof OPERATIONS)[number]
  assetType?: (typeof ASSET_TYPES)[number]
  /** ISO 8601 rolling-window duration. */
  window?: (typeof WINDOWS)[number]
}>

/**
 * Reads over an account's limits and current usage, as the SDK contract's
 * `AccountLimitsClient`.
 *
 * A dedicated client rather than a method on `AccountsClient`, matching this
 * SDK's pattern: every distinct resource type — accounts, deposits, deposit
 * addresses, transactions, transfers, withdrawals, fiat accounts — gets its
 * own client class rather than being folded into a sibling's. `limitsUsage` is its own resource with its own
 * wire shape, so it gets its own class too.
 *
 * {@link get} is an **ordinary typed read** (the classification for every
 * by-id read in this SDK): it needs no device signature. Neither the public
 * reference nor the Owner-authorization registry names a signed "limits"
 * operation.
 *
 * The API additionally rejects `window=PT24H` combined with
 * `operation=fiat_linking` or `operation=deposit_return_count`. That
 * constraint is not pre-validated here: it is a business rule about which
 * *values* of two independent query parameters may combine, not a structural
 * rule about the request shape, and this SDK's existing cross-field query
 * checks (`pageAfter`/`pageBefore` mutual exclusion on every paged list) are
 * all of the latter kind. Rejecting it locally would mean this SDK
 * hard-codes a business rule that can change on the service side without a
 * client release to match; the service's own `400` is the source of truth.
 *
 * Not constructible by a consumer: exported from `index.ts` as a type only,
 * and the `#transport` field makes the type nominal.
 */
export class AccountLimitsClient {
  readonly #transport: DaaTransport

  /** @internal Constructed only through the internal user-client factory. */
  constructor(transport: DaaTransport) {
    this.#transport = transport
    Object.freeze(this)
  }

  /**
   * Read one account's limits and current usage.
   *
   * @param accountId The service-assigned identifier. The public reference
   *   types this path parameter `^\d{1,10}$`; anything else is rejected
   *   locally rather than sent, because it cannot resolve on the service side.
   * @param query Optional `operation`/`assetType`/`window` filters.
   * @throws DaaError with `detail.kind === 'contract_violation'` for a
   *   rejected `accountId` or query, or a response the SDK cannot read, and
   *   `detail.kind === 'api'` for a status other than the documented `200`
   *   (including the `400` the API returns for `window=PT24H` combined
   *   with `operation=fiat_linking`/`deposit_return_count`);
   *   `detail.kind === 'transport'` if the consumer's transport throws, with the
   *   thrown value as `err.cause`.
   */
  async get(accountId: string, query?: AccountLimitsUsageQuery): Promise<AccountLimitsUsage> {
    if (!ACCOUNT_ID_PATTERN.test(accountId)) {
      throw contractViolation('accountId must match ^\\d{1,10}$')
    }

    return readResource({
      transport: this.#transport,
      path: ACCOUNT_LIMITS_USAGE_PATH_PREFIX + accountId + ACCOUNT_LIMITS_USAGE_PATH_SUFFIX,
      query: accountLimitsUsageQuery(query),
      decode: toAccountLimitsUsage,
    })
  }
}

function accountLimitsUsageQuery(query: AccountLimitsUsageQuery | undefined): string | null {
  if (query === undefined) return null
  if (typeof query !== 'object' || query === null || Array.isArray(query)) {
    throw contractViolation('account limits usage query must be an object')
  }

  const parts: string[] = []
  appendEnum(parts, 'operation', query.operation, OPERATIONS)
  appendEnum(parts, 'assetType', query.assetType, ASSET_TYPES)
  appendEnum(parts, 'window', query.window, WINDOWS)
  return parts.length === 0 ? null : parts.join('&')
}
