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
import { contractViolation } from '../errors'
import type { Account } from '../models/Account'
import type { CreateAccountRequest } from '../models/CreateAccountRequest'
import type { Page } from '../models/Page'
import type { DaaTransport } from '../transport/DaaTransport'
import { requireBodyObject, requireKnownProperties } from '../validation/requestBody'
import { isUuid, isUuidV4 } from '../validation/uuid'
import { toAccount, toAccounts } from '../wire/accountPayload'
import { readPage } from './pagination'
import {
  append,
  appendEnum,
  appendEnums,
  appendString,
  appendStrings,
  appendUuid,
} from './queryParameters'
import { readResource } from './resourceRequest'
import { postSignedResource, type DaaUserSigning } from './signedResource'

/**
 * `GET /v1/accounts/{accountId}` — the **public** path, which is what a
 * consumer's transport is handed. The SDK contract gives canonical paths in
 * this form, such as `/v1/accounts/transfers`.
 */
/**
 * The RFC 3986 unreserved set, which is what the native SDKs' request type
 * enforces on a whole path. Anything outside it — `%`, `/`, `?`, `#`, a control
 * character — is refused before a request is built.
 */
const SAFE_PATH_SEGMENT = /^[A-Za-z0-9._~-]+$/

const ACCOUNT_PATH_PREFIX = '/v1/accounts/'
const ACCOUNT_COLLECTION_PATH = '/v1/accounts'

/**
 * The properties the Owner-authorization registry's `create_account` schema
 * names, in the order it names them.
 *
 * Order matters because these are the bytes that get signed: the body is
 * serialized once from this shape and that exact slice is hashed into
 * `body_sha256` and put on the wire. Building it here rather than forwarding
 * the caller's object also means the property order does not vary with how the
 * caller happened to write its literal.
 */
const CREATE_ACCOUNT_PROPERTIES = Object.freeze([
  'idempotencyKey',
  'clientEntityId',
  'custodyType',
  'type',
  'purpose',
  'description',
  'blockchain',
])

export type AccountListQuery = Readonly<{
  custodyType?: 'omnibus' | 'segregated' | 'self'
  clientEntityId?: string
  type?: 'first_party' | 'third_party'
  isAttributed?: boolean
  purpose?: 'custody' | 'payments'
  status?: readonly ('active' | 'pending' | 'rejected' | 'archived')[]
  description?: string
  currencies?: readonly string[]
  groupId?: string
  from?: string
  to?: string
  pageAfter?: string
  pageBefore?: string
  pageSize?: number
}>

/**
 * Reads over DAA accounts, plus the signed account create, as the SDK
 * contract's `AccountsClient`.
 *
 * {@link list} returns a page whose navigation is derived only from same-origin
 * RFC 8288 links bound to this collection.
 *
 * An account read is an **ordinary typed read**: it needs no device signature.
 * {@link create} is the opposite: it is an Owner-authorized write, so it
 * carries an `X-Device-Authorization` bound to the exact bytes it sends and
 * cannot happen without the registered AuthKey `forUser` supplies.
 *
 * Not constructible by a consumer: exported from `index.ts` as a type only, and
 * the `#transport` field makes the type nominal.
 */
export class AccountsClient {
  readonly #transport: DaaTransport
  readonly #publicApiOrigin: string
  readonly #signing: DaaUserSigning

  /** @internal Constructed only through `createDaaUserClient`. */
  constructor(transport: DaaTransport, publicApiOrigin: string, signing: DaaUserSigning) {
    this.#transport = transport
    this.#publicApiOrigin = publicApiOrigin
    this.#signing = signing
    Object.freeze(this)
  }

  /** List accounts and retain the API's opaque navigation queries unchanged. */
  async list(query?: AccountListQuery): Promise<Page<Account>> {
    return readPage({
      transport: this.#transport,
      publicApiOrigin: this.#publicApiOrigin,
      path: ACCOUNT_COLLECTION_PATH,
      query: accountListQuery(query),
      decode: toAccounts,
    })
  }

  /**
   * Read one account.
   *
   * @param accountId The service-assigned identifier.
   * @throws DaaError with `detail.kind === 'contract_violation'` for a rejected
   *   `accountId` or a response the SDK cannot read, and `detail.kind === 'api'`
   *   for a status other than the documented `200`; `detail.kind === 'transport'`
   *   if the consumer's transport throws, with the thrown value as `err.cause`.
   */
  async get(accountId: string): Promise<Account> {
    // A path separator would silently extend the path into a sibling route rather
    // than fail: "acct-1/transfers" addresses /v1/accounts/acct-1/transfers, a
    // real and different operation. An empty id would likewise address the
    // collection instead of a member. Nothing is sent in either case.
    //
    // Rejecting only a literal `/` is not enough here, and this SDK has less to
    // fall back on than the native ones: their request type refuses any
    // character outside the RFC 3986 unreserved set, so a percent-encoded
    // separator never reaches the wire. `DaaTransport` is an interface a
    // consumer implements, so there is no equivalent runtime check downstream —
    // "acct-1%2Ftransfers" would be concatenated verbatim and reintroduce the
    // route confusion the moment anything decodes it. So the id is held to the
    // unreserved set, which excludes `%` along with everything else risky.
    // `.` is itself unreserved, so the pattern alone admits the dot-segments
    // `.` and `..` — which resolve upward rather than naming a member. The
    // native request type rejects them separately for the same reason.
    if (!SAFE_PATH_SEGMENT.test(accountId) || accountId === '.' || accountId === '..') {
      throw contractViolation(
        'accountId must be a single non-empty path segment of unreserved characters',
      )
    }

    return readResource({
      transport: this.#transport,
      path: ACCOUNT_PATH_PREFIX + accountId,
      decode: toAccount,
    })
  }

  /**
   * Create a self-custody account, authorized by the registered device key.
   *
   * The body is validated, serialized **once**, and that exact byte slice is
   * both hashed into the authorization's `body_sha256` claim and sent as the
   * request entity. Nothing between here and the transport re-serializes it,
   * which is the whole point: a re-encoding that changed so much as a space
   * would produce a signature over bytes the service never receives.
   *
   * Neither the method nor the path is chosen here. `postSignedResource`
   * resolves both from the registry entry for `create_account`, so a signed
   * write cannot be aimed somewhere the operation does not name.
   *
   * @throws DaaError with `detail.kind === 'contract_violation'` for a request
   *   the registry schema would reject, for an AuthKey that is not yet
   *   registered — the create is refused locally, before anything is signed or
   *   sent — for a rejected or replayed authorization (including a key that is
   *   no longer active: DAA has no revoked-credential code, so this never
   *   throws `device_revoked`), and for a response the SDK cannot read;
   *   `detail.kind === 'api'` for a status other than the documented `201`; and
   *   `detail.kind === 'transport'` if the consumer's transport throws, with the
   *   thrown value as `err.cause` and the request's `idempotencyKey` on the
   *   detail.
   */
  async create(request: CreateAccountRequest): Promise<Account> {
    const bodyBytes = serializeBody(createAccountBody(request))
    return postSignedResource({
      transport: this.#transport,
      operation: 'create_account',
      authKey: await this.#signing.resolveAuthKey(),
      authKeyId: this.#signing.authKeyId,
      bodyBytes,
      // The contract documents exactly 201, with a Location header. Another
      // 2xx is an observable API failure rather than a silently accepted
      // variant, the same rule the by-id reads apply to 200.
      expectedStatus: 201,
      decode: toAccount,
    })
  }
}

/**
 * Project a validated request onto the registry's `create_account` shape.
 *
 * Returned rather than serialized here so the caller can hold the one byte
 * slice this body becomes; see {@link AccountsClient.create}.
 */
function createAccountBody(request: CreateAccountRequest): object {
  requireBodyObject(request, 'account create request')
  requireKnownProperties(request, CREATE_ACCOUNT_PROPERTIES, 'account create request')

  const { idempotencyKey, clientEntityId, custodyType, type, purpose, description, blockchain } =
    request

  // UUID v4 specifically, which is stricter than the registry's `format: uuid`
  // (DAA only parses it). The contract's own
  // `SelfCustodyAccountCreationRequest` documents this field as "UUID v4
  // identifying this account-creation attempt", and this SDK already holds
  // `GenerateAddressRequest.idempotencyKey` to the same rule. The transfer
  // create is deliberately not held to it — nothing in its contract says v4.
  if (typeof idempotencyKey !== 'string' || !isUuidV4(idempotencyKey)) {
    throw contractViolation('idempotencyKey must be a UUID v4')
  }
  if (typeof clientEntityId !== 'string' || !isUuid(clientEntityId)) {
    throw contractViolation('clientEntityId is required and must be a UUID')
  }
  if (custodyType !== 'self') {
    throw contractViolation('custodyType must be self')
  }
  if (type !== 'third_party') {
    throw contractViolation('type must be third_party')
  }
  if (purpose !== 'custody') {
    throw contractViolation('purpose must be custody')
  }
  if (typeof description !== 'string') {
    throw contractViolation('description must be a string')
  }
  if (description.length > 255) {
    throw contractViolation('description must be 255 characters or fewer')
  }
  if (blockchain !== undefined && (typeof blockchain !== 'string' || blockchain.length === 0)) {
    throw contractViolation('blockchain must be a non-empty string when supplied')
  }

  // `blockchain` is the one optional property here: an omitted value is left
  // out of the object rather than set to `undefined`, so `JSON.stringify`
  // drops it identically either way, but only the omission says so in the
  // source. Every other property is required and validated above.
  return {
    idempotencyKey,
    clientEntityId,
    custodyType,
    type,
    purpose,
    description,
    ...(blockchain === undefined ? {} : { blockchain }),
  }
}

function accountListQuery(query: AccountListQuery | undefined): string | null {
  if (query === undefined) return null
  if (typeof query !== 'object' || query === null || Array.isArray(query)) {
    throw contractViolation('account list query must be an object')
  }
  if (query.pageAfter !== undefined && query.pageBefore !== undefined) {
    throw contractViolation('pageAfter and pageBefore cannot be used together')
  }

  const parts: string[] = []
  appendEnum(parts, 'custodyType', query.custodyType, ['omnibus', 'segregated', 'self'])
  appendUuid(parts, 'clientEntityId', query.clientEntityId)
  appendEnum(parts, 'type', query.type, ['first_party', 'third_party'])
  if (query.isAttributed !== undefined) {
    if (typeof query.isAttributed !== 'boolean') {
      throw contractViolation('isAttributed must be a boolean')
    }
    append(parts, 'isAttributed', String(query.isAttributed))
  }
  appendEnum(parts, 'purpose', query.purpose, ['custody', 'payments'])
  appendEnums(parts, 'status', query.status, ['active', 'pending', 'rejected', 'archived'])
  appendString(parts, 'description', query.description)
  appendStrings(parts, 'currencies', query.currencies)
  appendUuid(parts, 'groupId', query.groupId)
  appendString(parts, 'from', query.from)
  appendString(parts, 'to', query.to)
  appendString(parts, 'pageAfter', query.pageAfter)
  appendString(parts, 'pageBefore', query.pageBefore)
  if (query.pageSize !== undefined) {
    if (!Number.isInteger(query.pageSize) || query.pageSize < 1) {
      throw contractViolation('pageSize must be a positive integer')
    }
    append(parts, 'pageSize', String(query.pageSize))
  }
  return parts.length === 0 ? null : parts.join('&')
}
