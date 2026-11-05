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
import type { Wire, WireInstruction, WireSummary } from '../models/Wire'
import type { DaaTransport } from '../transport/DaaTransport'
import { isUuid } from '../validation/uuid'
import { toWire, toWireInstruction, toWireSummaries } from '../wire/wirePayload'
import { appendString, appendUuid } from './queryParameters'
import { readResource } from './resourceRequest'

const WIRE_COLLECTION_PATH = '/v1/banks/wires'
const WIRE_PATH_PREFIX = '/v1/banks/wires/'

/** The wire collection's list query: `clientEntityId` is optional. */
export type WireFiatAccountListQuery = Readonly<{
  clientEntityId?: string
}>

/**
 * A public Accounts API `accountId` query value. These are strings, including
 * numeric IDs — the same reason `AccountsClient.get` types its parameter
 * `string` rather than `UUID`.
 */
export type PublicAccountId = string

/** Optional query accepted by {@link WireFiatAccountsClient.getInstructions}. */
export type WireInstructionQuery = Readonly<{
  accountId?: PublicAccountId
}>

/**
 * Reads over wire fiat accounts.
 *
 * Every operation here is an **ordinary typed read** — fiat-account list and
 * get and the receiving-instructions read are all unsigned — so, like
 * `AccountsClient.get`, none of it needs a device signature.
 *
 * {@link list} returns the API's **unpaginated list shape**: a plain `data`
 * array, not this SDK's opaque-cursor `Page<T>`. {@link get} and
 * {@link getInstructions} are separate SDK methods and response types by
 * design: {@link get} returns the linked bank account, {@link getInstructions}
 * returns Circle receiving instructions for it. {@link getInstructions} is a
 * plain typed read of the public instruction route: it returns Circle's
 * receiving instructions and does not resolve a self-custody pass-through
 * account.
 *
 * Not constructible by a consumer: exported from `index.ts` as a type only,
 * and the `#transport` field makes the type nominal.
 */
export class WireFiatAccountsClient {
  readonly #transport: DaaTransport

  /** @internal Constructed only through `createDaaUserClient`. */
  constructor(transport: DaaTransport) {
    this.#transport = transport
    Object.freeze(this)
  }

  /**
   * List wire fiat accounts.
   *
   * `clientEntityId` is optional here — unlike `AchFiatAccountsClient.list`,
   * where it is required. This is a deliberate asymmetry, not a typo:
   * `WireFiatAccountListQuery.clientEntityId` is optional and
   * `AchFiatAccountListQuery.clientEntityId` is required, because ACH listing
   * covers third-party accounts only.
   *
   * @throws DaaError with `detail.kind === 'contract_violation'` for an
   *   invalid query or a response the SDK cannot read, and
   *   `detail.kind === 'api'` for a status other than the documented `200`;
   *   `detail.kind === 'transport'` if the consumer's transport throws, with the
   *   thrown value as `err.cause`.
   */
  async list(query?: WireFiatAccountListQuery): Promise<ReadonlyArray<WireSummary>> {
    return readResource({
      transport: this.#transport,
      path: WIRE_COLLECTION_PATH,
      query: wireListQuery(query),
      decode: toWireSummaries,
    })
  }

  /**
   * Read one wire fiat account.
   *
   * @param fiatAccountId The service-assigned UUID.
   * @throws DaaError with `detail.kind === 'contract_violation'` for a
   *   rejected `fiatAccountId` or a response the SDK cannot read, and
   *   `detail.kind === 'api'` for a status other than the documented `200`;
   *   `detail.kind === 'transport'` if the consumer's transport throws, with the
   *   thrown value as `err.cause`.
   */
  async get(fiatAccountId: string): Promise<Wire> {
    if (!isUuid(fiatAccountId)) {
      throw contractViolation('fiatAccountId must be a UUID')
    }

    return readResource({
      transport: this.#transport,
      path: WIRE_PATH_PREFIX + fiatAccountId,
      decode: toWire,
    })
  }

  /**
   * Read Circle receiving instructions for a wire fiat account.
   *
   * A plain typed read of the public instruction route — see the class doc.
   *
   * @param fiatAccountId The service-assigned UUID.
   * @param query Optional public `accountId`. The wire instruction route
   *   accepts this parameter; the ACH route does not.
   * @throws DaaError with `detail.kind === 'contract_violation'` for a
   *   rejected `fiatAccountId`/`accountId` or a response the SDK cannot read,
   *   and `detail.kind === 'api'` for a status other than the documented
   *   `200`; `detail.kind === 'transport'` if the consumer's transport throws,
   *   with the thrown value as `err.cause`.
   */
  async getInstructions(
    fiatAccountId: string,
    query?: WireInstructionQuery,
  ): Promise<WireInstruction> {
    if (!isUuid(fiatAccountId)) {
      throw contractViolation('fiatAccountId must be a UUID')
    }

    return readResource({
      transport: this.#transport,
      path: WIRE_PATH_PREFIX + fiatAccountId + '/instructions',
      query: wireInstructionQuery(query),
      decode: toWireInstruction,
    })
  }
}

function wireListQuery(query: WireFiatAccountListQuery | undefined): string | null {
  if (query === undefined) return null
  if (typeof query !== 'object' || query === null || Array.isArray(query)) {
    throw contractViolation('wire list query must be an object')
  }

  const parts: string[] = []
  appendUuid(parts, 'clientEntityId', query.clientEntityId)
  return parts.length === 0 ? null : parts.join('&')
}

function wireInstructionQuery(query: WireInstructionQuery | undefined): string | null {
  if (query === undefined) return null
  if (typeof query !== 'object' || query === null || Array.isArray(query)) {
    throw contractViolation('wire instruction query must be an object')
  }

  const parts: string[] = []
  appendString(parts, 'accountId', query.accountId)
  return parts.length === 0 ? null : parts.join('&')
}
