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

import { serializeBody } from '../crypto/serialization'
import { contractViolation, idempotencyConflict } from '../errors'
import type { AddressObject } from '../models/AddressObject'
import type { GenerateAddressRequest } from '../models/GenerateAddressRequest'
import type { Page } from '../models/Page'
import type { DaaTransport } from '../transport/DaaTransport'
import { headerValueIgnoringCase } from '../transport/headers'
import { isUuid, isUuidV4 } from '../validation/uuid'
import { toAddressObject, toAddressObjects } from '../wire/addressObjectPayload'
import { isDaaStatus } from '../wire/daaStatusCodes'
import { readDaaStatusCode } from '../wire/errorEnvelope'
import { readPage } from './pagination'
import { appendEnum, appendString, appendUuid } from './queryParameters'
import { postResource, readResource } from './resourceRequest'

/**
 * `GET /v1/accounts/addresses/deposit/{depositId}` — the **public** path,
 * which is what a consumer's transport is handed, as `AccountsClient`
 * documents for `/v1/accounts/{accountId}`.
 */
const DEPOSIT_ADDRESS_PATH_PREFIX = '/v1/accounts/addresses/deposit/'
const DEPOSIT_ADDRESS_COLLECTION_PATH = '/v1/accounts/addresses/deposit'

/** Filters and keyset pagination accepted by the deposit-address collection. */
export type DepositAddressListQuery = Readonly<{
  custodyType?: 'omnibus' | 'segregated' | 'self'
  accountId?: string
  chain?: string
  currency?: string
  from?: string
  to?: string
  pageAfter?: string
  pageBefore?: string
  pageSize?: number
}>

/**
 * Reads over DAA deposit addresses, as the SDK contract's
 * `DepositAddressesClient`.
 *
 * {@link get} reads an existing address. {@link create} is the unsigned
 * create-or-resolve call for a named account: DAA creates the address for an
 * omnibus `accountId` and returns the already-authoritative address for a
 * segregated/self-custody one. See `GenerateAddressRequest`'s class doc for
 * why this SDK's typed client does not expose the broader Accounts API's
 * omission of `accountId` (the caller's omnibus master account). {@link list}
 * returns trusted pages bound to the deposit-address collection.
 *
 * {@link create} throws `idempotency_conflict` for a `409` with
 * `IDEMPOTENCY_KEY_REUSED` (`420034`). DAA sends it when an omnibus create
 * reuses an `idempotencyKey` that was already used for a different account.
 * The same key for the same account returns the original address, even with a
 * different `chain` or `currency`. A segregated or self-custody create only
 * resolves an existing address, so it never sends it. Any other `409` stays
 * `api`.
 *
 * A deposit-address read is an **ordinary typed read**, the same
 * classification `AccountsClient.get` carries: it needs no device signature.
 * It is reachable the same way: through the `DaaUserClient` that `forUser`
 * returns for a real user context.
 *
 * Not constructible by a consumer: exported from `index.ts` as a type only,
 * and the `#transport` field makes the type nominal.
 */
export class DepositAddressesClient {
  readonly #transport: DaaTransport
  readonly #publicApiOrigin: string

  /** @internal Constructed only through `createDaaUserClient`. */
  constructor(transport: DaaTransport, publicApiOrigin: string) {
    this.#transport = transport
    this.#publicApiOrigin = publicApiOrigin
    Object.freeze(this)
  }

  /** List deposit addresses and retain the API's opaque navigation queries unchanged. */
  async list(query?: DepositAddressListQuery): Promise<Page<AddressObject>> {
    return readPage({
      transport: this.#transport,
      publicApiOrigin: this.#publicApiOrigin,
      path: DEPOSIT_ADDRESS_COLLECTION_PATH,
      query: depositAddressListQuery(query),
      decode: toAddressObjects,
    })
  }

  /**
   * Read one deposit address.
   *
   * @param depositId The service-assigned identifier. The service types this
   *   as a required UUID — a genuine UUID, not
   *   an arbitrary account-style id — so a value that is not UUID-formatted
   *   is rejected locally rather than sent: it cannot resolve to an address on
   *   the service side, and a UUID-formatted identifier also contains none of the
   *   characters (`/`, `%`, `.`, control bytes) that could redirect the
   *   request into a sibling route, the concern `AccountsClient.get`'s
   *   character-class check exists for.
   * @throws DaaError with `detail.kind === 'contract_violation'` for a
   *   rejected `depositId` or a response the SDK cannot read, and
   *   `detail.kind === 'api'` for a status other than the documented `200`;
   *   `detail.kind === 'transport'` if the consumer's transport throws, with the
   *   thrown value as `err.cause`.
   */
  async get(depositId: string): Promise<AddressObject> {
    if (!isUuid(depositId)) {
      throw contractViolation(
        'depositId must be a UUID — the service types it as one, and anything else cannot resolve to a deposit address',
      )
    }

    return readResource({
      transport: this.#transport,
      path: DEPOSIT_ADDRESS_PATH_PREFIX + depositId,
      decode: toAddressObject,
    })
  }

  /**
   * Create the deposit address for a named omnibus account, or resolve a
   * segregated/self-custody account's already-authoritative one.
   *
   * The request has no `custodyType`; DAA derives custody from `accountId` when
   * it is omitted. That is the only option that cannot disagree with the
   * account's authoritative custody type.
   *
   * `accountId` is required — see {@link GenerateAddressRequest}'s class doc
   * for why this SDK does not expose the broader Accounts API's omission of
   * `accountId` (the caller's omnibus master account).
   *
   * This call is unsigned by contract. Its body is projected to the documented
   * wire shape, serialized once, and the resulting bytes are sent unchanged.
   *
   * @throws DaaError with `detail.kind === 'contract_violation'` for an invalid
   *   request or a response the SDK cannot read; `idempotency_conflict`, with
   *   the request's key, for a `409` with `IDEMPOTENCY_KEY_REUSED` (`420034`):
   *   the key was already used for a different account, so reconcile the
   *   original create with that key and do not mint a new key for it;
   *   `detail.kind === 'api'` for any other status than the documented `201`;
   *   and `detail.kind === 'transport'` if the consumer's transport
   *   throws, with the thrown value as `err.cause` and the request's
   *   `idempotencyKey` on the detail.
   */
  async create(request: GenerateAddressRequest): Promise<AddressObject> {
    if (typeof request !== 'object' || request === null || Array.isArray(request)) {
      throw contractViolation('deposit address request must be an object')
    }

    const { idempotencyKey, accountId, currency, chain } = request
    if (typeof idempotencyKey !== 'string' || !isUuidV4(idempotencyKey)) {
      throw contractViolation('idempotencyKey must be a UUID v4')
    }
    if (typeof accountId !== 'string' || accountId.length === 0) {
      throw contractViolation('accountId must be a non-empty string')
    }
    if (currency !== 'USD' && currency !== 'EUR') {
      throw contractViolation('currency must be USD or EUR')
    }
    // `chain` is optional (resolves to the account's home blockchain when
    // omitted) and, when supplied, is checked only for a plausible shape, not
    // against a hardcoded catalog — see `models/GenerateAddressRequest.ts`'s
    // `DEPOSIT_ADDRESS_CHAINS` doc for why a closed local allowlist here is a
    // forward-compatibility hazard rather than a safety net.
    if (chain !== undefined && (typeof chain !== 'string' || chain.length === 0)) {
      throw contractViolation('chain must be a non-empty string when supplied')
    }

    const bodyBytes = serializeBody({
      idempotencyKey,
      accountId,
      currency,
      ...(chain === undefined ? {} : { chain }),
    })
    return postResource({
      transport: this.#transport,
      path: '/v1/accounts/addresses/deposit',
      query: null,
      headers: { 'Content-Type': 'application/json' },
      bodyBytes,
      expectedStatus: 201,
      decode: toAddressObject,
      // Gated on both the status and the code, as on the signed writes. The
      // call is unsigned, so the key is the one this request was checked with.
      failure: (response) =>
        response.status === 409 &&
        isDaaStatus(readDaaStatusCode(response.bodyBytes), 'IDEMPOTENCY_KEY_REUSED')
          ? idempotencyConflict(
              idempotencyKey,
              headerValueIgnoringCase(response.headers, 'X-Request-Id'),
            )
          : null,
    })
  }
}

function depositAddressListQuery(query: DepositAddressListQuery | undefined): string | null {
  if (query === undefined) return null
  if (typeof query !== 'object' || query === null || Array.isArray(query)) {
    throw contractViolation('deposit address list query must be an object')
  }
  if (query.pageAfter !== undefined && query.pageBefore !== undefined) {
    throw contractViolation('pageAfter and pageBefore cannot be used together')
  }

  const parts: string[] = []
  appendEnum(parts, 'custodyType', query.custodyType, ['omnibus', 'segregated', 'self'])
  appendString(parts, 'accountId', query.accountId)
  appendString(parts, 'chain', query.chain)
  appendString(parts, 'currency', query.currency)
  appendString(parts, 'from', query.from)
  appendString(parts, 'to', query.to)
  // Unlike account cursors, the service models deposit-address cursors as UUID ids.
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
