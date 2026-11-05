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
import type { ACH, ACHInstruction } from '../models/Ach'
import type { DaaTransport } from '../transport/DaaTransport'
import { isUuid } from '../validation/uuid'
import { toAch, toAchInstruction, toAchList } from '../wire/achPayload'
import { appendUuid } from './queryParameters'
import { readResource } from './resourceRequest'

const ACH_COLLECTION_PATH = '/v1/banks/ach'
const ACH_PATH_PREFIX = '/v1/banks/ach/'

/**
 * The ACH collection's list query: unlike wire's, `clientEntityId` is
 * **required** for the ACH collection read, because ACH listing covers
 * third-party accounts only.
 */
export type AchFiatAccountListQuery = Readonly<{
  clientEntityId: string
}>

/**
 * Reads over ACH fiat accounts.
 *
 * Every operation here is an **ordinary typed read with no device signature**,
 * the same classification `WireFiatAccountsClient` carries.
 *
 * {@link list} requires `clientEntityId` — see that field's doc — and, like
 * `get`, decodes the full `ACH` projection, for consistency with the by-id
 * read, so there is no separate `ACHSummary` the way `WireSummary` exists for
 * wire. {@link getInstructions} is a plain typed read of the public
 * instruction route, like `WireFiatAccountsClient.getInstructions`: it returns
 * Circle's receiving instructions and does not resolve a self-custody
 * pass-through account. Unlike wire's instruction read, it takes no query: the
 * ACH route has no public `accountId`.
 *
 * An environment without `GET /v1/banks/ach` surfaces the ordinary `api` error
 * for whatever status it returns; this client has no distinguished
 * unsupported-capability error.
 *
 * Not constructible by a consumer: exported from `index.ts` as a type only,
 * and the `#transport` field makes the type nominal.
 */
export class AchFiatAccountsClient {
  readonly #transport: DaaTransport

  /** @internal Constructed only through `createDaaUserClient`. */
  constructor(transport: DaaTransport) {
    this.#transport = transport
    Object.freeze(this)
  }

  /**
   * List ACH fiat accounts for one client entity.
   *
   * `query` and `query.clientEntityId` are both required — the signature is
   * `list(query: AchFiatAccountListQuery)`, not `query?`. See
   * {@link AchFiatAccountListQuery} for why.
   *
   * @throws DaaError with `detail.kind === 'contract_violation'` for a
   *   missing or invalid `clientEntityId`, or a response the SDK cannot read,
   *   and `detail.kind === 'api'` for a status other than the documented
   *   `200`; `detail.kind === 'transport'` if the consumer's transport throws,
   *   with the thrown value as `err.cause`.
   */
  async list(query: AchFiatAccountListQuery): Promise<ReadonlyArray<ACH>> {
    if (typeof query !== 'object' || query === null || Array.isArray(query)) {
      throw contractViolation('ach list query must be an object')
    }

    const parts: string[] = []
    if (query.clientEntityId === undefined) {
      throw contractViolation('clientEntityId is required for the ACH collection read')
    }
    appendUuid(parts, 'clientEntityId', query.clientEntityId)

    return readResource({
      transport: this.#transport,
      path: ACH_COLLECTION_PATH,
      query: parts.join('&'),
      decode: toAchList,
    })
  }

  /**
   * Read one ACH fiat account.
   *
   * @param fiatAccountId The service-assigned UUID.
   * @throws DaaError with `detail.kind === 'contract_violation'` for a
   *   rejected `fiatAccountId` or a response the SDK cannot read, and
   *   `detail.kind === 'api'` for a status other than the documented `200`;
   *   `detail.kind === 'transport'` if the consumer's transport throws, with the
   *   thrown value as `err.cause`.
   */
  async get(fiatAccountId: string): Promise<ACH> {
    if (!isUuid(fiatAccountId)) {
      throw contractViolation('fiatAccountId must be a UUID')
    }

    return readResource({
      transport: this.#transport,
      path: ACH_PATH_PREFIX + fiatAccountId,
      decode: toAch,
    })
  }

  /**
   * Read Circle receiving instructions for an ACH fiat account.
   *
   * A plain typed read of the public instruction route — see the class doc.
   *
   * @param fiatAccountId The service-assigned UUID.
   * @throws DaaError with `detail.kind === 'contract_violation'` for a
   *   rejected `fiatAccountId` or a response the SDK cannot read, and
   *   `detail.kind === 'api'` for a status other than the documented `200`;
   *   `detail.kind === 'transport'` if the consumer's transport throws, with the
   *   thrown value as `err.cause`.
   */
  async getInstructions(fiatAccountId: string): Promise<ACHInstruction> {
    if (!isUuid(fiatAccountId)) {
      throw contractViolation('fiatAccountId must be a UUID')
    }

    return readResource({
      transport: this.#transport,
      path: ACH_PATH_PREFIX + fiatAccountId + '/instructions',
      decode: toAchInstruction,
    })
  }
}
