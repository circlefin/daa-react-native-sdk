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
import type {
  CreateTransferAmount,
  CreateTransferDestination,
  CreateTransferRequest,
  CreateTransferRiskSignals,
  CreateTransferSource,
} from '../models/CreateTransferRequest'
import type { Transfer } from '../models/Transfer'
import type { Page } from '../models/Page'
import type { DaaTransport } from '../transport/DaaTransport'
import { requireBodyObject, requireKnownProperties } from '../validation/requestBody'
import { isUuid } from '../validation/uuid'
import { JSON_NUMBER } from '../wire/jsonNumber'
import { toTransfer, toTransfers } from '../wire/transferPayload'
import { readPage } from './pagination'
import { append, appendEnum, appendString, appendUuid } from './queryParameters'
import { readResource } from './resourceRequest'
import { postSignedResource, type DaaUserSigning } from './signedResource'

/**
 * `GET /v1/accounts/transfers/{transferId}` — the **public** path, exactly as
 * for Accounts (`AccountsClient.ts`). The registry's
 * `"canonical_path": "/v1/accounts/transfers"` and the `Location` header of
 * `/v1/accounts/transfers/<id>` on create both use it.
 */
const TRANSFER_PATH_PREFIX = '/v1/accounts/transfers/'
const TRANSFER_COLLECTION_PATH = '/v1/accounts/transfers'

/**
 * The properties the Owner-authorization registry's `transfer` schema names, in
 * the order it names them, at each level of the body.
 *
 * Order matters because these are the bytes that get signed: the body is
 * serialized once from these shapes and that exact slice is hashed into
 * `body_sha256` and put on the wire. Building it here rather than forwarding
 * the caller's object also means the property order does not vary with how the
 * caller happened to write its literal. Every one of these objects is
 * `additionalProperties: false` in the registry, so each level is checked, not
 * just the top.
 */
const TRANSFER_PROPERTIES = Object.freeze([
  'idempotencyKey',
  'source',
  'destination',
  'amount',
  'riskSignals',
])
const TRANSFER_LOCATION_PROPERTIES = Object.freeze(['type', 'id'])
const TRANSFER_VERIFIED_BLOCKCHAIN_PROPERTIES = Object.freeze(['type', 'addressId'])
const TRANSFER_AMOUNT_PROPERTIES = Object.freeze(['amount', 'currency'])
const TRANSFER_RISK_SIGNAL_PROPERTIES = Object.freeze(['ipAddress', 'sessionId', 'deviceId'])

export type TransferListQuery = Readonly<{
  /** Select a backing source explicitly; omitted derives from `accountId` or defaults to omnibus. */
  custodyType?: 'omnibus' | 'segregated' | 'self'
  /** Match transfers where this public account id is either leg. */
  accountId?: string
  /** Match this source leg id. Leg ids are strings and are not necessarily UUIDs. */
  sourceAccountId?: string
  /** Match this destination leg id. Leg ids are strings and are not necessarily UUIDs. */
  destinationAccountId?: string
  /** Match transfers for one end-user sub-entity. */
  clientEntityId?: string
  sourceType?: 'account' | 'blockchain'
  destinationType?: 'account' | 'blockchain'
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

/*
 * A transfer id is a UUID, and is checked as one rather than as a generic path
 * segment.
 *
 * The SDK contract types this parameter `transferId: UUID`. That is
 * deliberately unlike `AccountsClient`, whose signature is
 * `accountId: string`, because public account ids are strings, including
 * numeric IDs. The two guards differ on purpose; applying one rule to
 * both would make one of them wrong.
 *
 * A UUID-formatted identifier contains none of the characters — `/`, `%`, `.`, control
 * bytes — that could redirect the request into a sibling route, so this subsumes
 * the path-segment check rather than merely differing from it.
 */
/**
 * Reads over DAA transfers, plus the signed transfer create, as the SDK
 * contract's `TransfersClient`.
 *
 * {@link list} retains the API's RFC 8288 navigation queries as opaque text.
 * {@link create} is an Owner-authorized write: it carries an
 * `X-Device-Authorization` bound to the exact bytes it sends and cannot happen
 * without the registered AuthKey `forUser` supplies.
 *
 * Not constructible by a consumer: exported from `index.ts` as a type only, and
 * the `#transport` field makes the type nominal.
 */
export class TransfersClient {
  readonly #transport: DaaTransport
  readonly #publicApiOrigin: string
  readonly #signing: DaaUserSigning

  /** @internal Constructed only through the internal user-client factory. */
  constructor(transport: DaaTransport, publicApiOrigin: string, signing: DaaUserSigning) {
    this.#transport = transport
    this.#publicApiOrigin = publicApiOrigin
    this.#signing = signing
    Object.freeze(this)
  }

  /** List transfers and retain the API's opaque navigation queries unchanged. */
  async list(query?: TransferListQuery): Promise<Page<Transfer>> {
    return readPage({
      transport: this.#transport,
      publicApiOrigin: this.#publicApiOrigin,
      path: TRANSFER_COLLECTION_PATH,
      query: transferListQuery(query),
      decode: toTransfers,
    })
  }

  /**
   * Read one transfer.
   *
   * @param transferId The service-assigned UUID. Values that are not
   *   UUID-formatted are rejected locally because they cannot resolve to a
   *   transfer on the service side.
   * @throws DaaError with `detail.kind === 'contract_violation'` for a rejected
   *   `transferId` or a response the SDK cannot read, and `detail.kind === 'api'`
   *   for a status other than the documented `200`; `detail.kind === 'transport'`
   *   if the consumer's transport throws, with the thrown value as `err.cause`.
   */
  async get(transferId: string): Promise<Transfer> {
    if (!isUuid(transferId)) {
      throw contractViolation('transferId must be a UUID')
    }

    return readResource({
      transport: this.#transport,
      path: TRANSFER_PATH_PREFIX + transferId,
      decode: toTransfer,
    })
  }

  /**
   * Create a transfer, authorized by the registered device key.
   *
   * The body is validated, serialized **once**, and that exact byte slice is
   * both hashed into the authorization's `body_sha256` claim and sent as the
   * request entity. Nothing between here and the transport re-serializes it,
   * which is the whole point: a re-encoding that changed so much as a space
   * would produce a signature over bytes the service never receives.
   *
   * Neither the method nor the path is chosen here. `postSignedResource`
   * resolves both from the registry entry for `transfer`, so a signed write
   * cannot be aimed somewhere the operation does not name.
   *
   * @throws DaaError with `detail.kind === 'contract_violation'` for a request
   *   the registry schema would reject, for an AuthKey that is not yet
   *   registered — the create is refused locally, before anything is signed or
   *   sent — for a rejected or replayed authorization (including a key that is
   *   no longer active: DAA has no revoked-credential code, so this never
   *   throws `device_revoked`), and for a response the SDK cannot read;
   *   `idempotency_conflict`, with the request's key, for a `409` with
   *   `IDEMPOTENCY_KEY_REUSED` (`420034`): reconcile the original transfer with
   *   the same key; do not mint a new key for it;
   *   `detail.kind === 'api'` for a status other than the documented `201`; and
   *   `detail.kind === 'transport'` if the consumer's transport throws, with the
   *   thrown value as `err.cause` and the request's `idempotencyKey` on the
   *   detail.
   */
  async create(request: CreateTransferRequest): Promise<Transfer> {
    const bodyBytes = serializeBody(createTransferBody(request))
    return postSignedResource({
      transport: this.#transport,
      operation: 'transfer',
      authKey: await this.#signing.resolveAuthKey(),
      authKeyId: this.#signing.authKeyId,
      bodyBytes,
      // The contract documents exactly 201, with a Location header. Another
      // 2xx is an observable API failure rather than a silently accepted
      // variant, the same rule the by-id reads apply to 200.
      expectedStatus: 201,
      decode: toTransfer,
    })
  }
}

/**
 * Project a validated request onto the registry's `transfer` shape.
 *
 * Returned rather than serialized here so the caller can hold the one byte
 * slice this body becomes; see {@link TransfersClient.create}.
 */
function createTransferBody(request: CreateTransferRequest): object {
  requireBodyObject(request, 'transfer create request')
  requireKnownProperties(request, TRANSFER_PROPERTIES, 'transfer create request')

  const { idempotencyKey, source, destination, amount, riskSignals } = request

  // The registry types this `format: uuid`, and nothing in the transfer
  // contract narrows it to v4 — unlike the account create, whose own contract
  // text says v4. Requiring more here would reject a key DAA accepts.
  if (typeof idempotencyKey !== 'string' || !isUuid(idempotencyKey)) {
    throw contractViolation('idempotencyKey must be a UUID')
  }

  return {
    idempotencyKey,
    ...(source === undefined ? {} : { source: transferSource(source) }),
    destination: transferDestination(destination),
    amount: transferAmount(amount),
    ...(riskSignals === undefined ? {} : { riskSignals: transferRiskSignals(riskSignals) }),
  }
}

function transferSource(source: CreateTransferSource): object {
  requireBodyObject(source, 'transfer source')
  requireKnownProperties(source, TRANSFER_LOCATION_PROPERTIES, 'transfer source')
  const { type, id } = source
  if (type !== 'account') {
    throw contractViolation('transfer source type must be account')
  }
  if (typeof id !== 'string' || id.length === 0) {
    throw contractViolation('transfer source id must be a non-empty string')
  }
  return { type, id }
}

/**
 * Both `oneOf` arms, kept apart by their discriminator.
 *
 * The registry requires a destination to match exactly one arm, and the two are
 * told apart by `type` alone — their required properties are disjoint (`id`
 * against `addressId`) and neither admits additional ones. So an unfamiliar
 * `type` is rejected here rather than guessed at: guessing would mean picking
 * an arm DAA would not have picked, and signing that.
 */
function transferDestination(destination: CreateTransferDestination): object {
  requireBodyObject(destination, 'transfer destination')
  const { type } = destination
  if (type === 'account') {
    requireKnownProperties(destination, TRANSFER_LOCATION_PROPERTIES, 'transfer destination')
    const { id } = destination
    if (typeof id !== 'string' || id.length === 0) {
      throw contractViolation('transfer destination id must be a non-empty string')
    }
    return { type, id }
  }
  if (type === 'verified_blockchain') {
    requireKnownProperties(
      destination,
      TRANSFER_VERIFIED_BLOCKCHAIN_PROPERTIES,
      'transfer destination',
    )
    const { addressId } = destination
    if (typeof addressId !== 'string' || !isUuid(addressId)) {
      throw contractViolation('transfer destination addressId must be a UUID')
    }
    return { type, addressId }
  }
  throw contractViolation('transfer destination type must be account or verified_blockchain')
}

function transferAmount(amount: CreateTransferAmount): object {
  requireBodyObject(amount, 'transfer amount')
  requireKnownProperties(amount, TRANSFER_AMOUNT_PROPERTIES, 'transfer amount')
  const { amount: amountValue, currency } = amount
  // The registry's `decimal` accepts a JSON string or a JSON number and then
  // parses it as an arbitrary-precision decimal, so it would also take forms
  // JSON itself does not write — a bare leading `.`, a trailing `.`, a leading
  // `+`. This narrows to the RFC 8259 number grammar the SDK already requires
  // of a `Money` on the way in (`wire/jsonNumber.ts`), so the same literal
  // means the same thing in both directions and the signed bytes are never
  // ambiguous.
  if (typeof amountValue !== 'string' || !JSON_NUMBER.test(amountValue)) {
    throw contractViolation('transfer amount must be a decimal string, e.g. "10.25"')
  }
  if (typeof currency !== 'string' || currency.length === 0) {
    throw contractViolation('transfer amount currency must be a non-empty string')
  }
  return { amount: amountValue, currency }
}

function transferRiskSignals(riskSignals: CreateTransferRiskSignals): object {
  requireBodyObject(riskSignals, 'transfer risk signals')
  requireKnownProperties(riskSignals, TRANSFER_RISK_SIGNAL_PROPERTIES, 'transfer risk signals')
  const { ipAddress, sessionId, deviceId } = riskSignals
  requireOptionalRiskSignal(ipAddress, 'ipAddress')
  requireOptionalRiskSignal(sessionId, 'sessionId')
  requireOptionalRiskSignal(deviceId, 'deviceId')
  // The registry requires none of these, so an object with none of them is a
  // valid `riskSignals` and is sent as the empty object the caller asked for.
  return {
    ...(ipAddress === undefined ? {} : { ipAddress }),
    ...(sessionId === undefined ? {} : { sessionId }),
    ...(deviceId === undefined ? {} : { deviceId }),
  }
}

function requireOptionalRiskSignal(value: string | undefined, name: string): void {
  if (value !== undefined && (typeof value !== 'string' || value.length === 0)) {
    throw contractViolation(`transfer risk signal ${name} must be a non-empty string`)
  }
}

function transferListQuery(query: TransferListQuery | undefined): string | null {
  if (query === undefined) return null
  if (typeof query !== 'object' || query === null || Array.isArray(query)) {
    throw contractViolation('transfer list query must be an object')
  }
  if (query.pageAfter !== undefined && query.pageBefore !== undefined) {
    throw contractViolation('pageAfter and pageBefore cannot be used together')
  }

  const parts: string[] = []
  appendEnum(parts, 'custodyType', query.custodyType, ['omnibus', 'segregated', 'self'])
  appendString(parts, 'accountId', query.accountId)
  appendString(parts, 'sourceAccountId', query.sourceAccountId)
  appendString(parts, 'destinationAccountId', query.destinationAccountId)
  appendUuid(parts, 'clientEntityId', query.clientEntityId)
  appendEnum(parts, 'sourceType', query.sourceType, ['account', 'blockchain'])
  appendEnum(parts, 'destinationType', query.destinationType, ['account', 'blockchain'])
  appendString(parts, 'from', query.from)
  appendString(parts, 'to', query.to)
  // Unlike account cursors, the service models transfer cursors as UUID transfer ids.
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
