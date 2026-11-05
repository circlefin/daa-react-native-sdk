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
  CreateWithdrawalAmount,
  CreateWithdrawalDestination,
  CreateWithdrawalRequest,
  CreateWithdrawalRiskSignals,
  CreateWithdrawalSource,
  CreateWithdrawalToAmount,
} from '../models/CreateWithdrawalRequest'
import type { Page } from '../models/Page'
import type { WithdrawalDetail } from '../models/Withdrawal'
import type { DaaTransport } from '../transport/DaaTransport'
import { requireBodyObject, requireKnownProperties } from '../validation/requestBody'
import { isUuid } from '../validation/uuid'
import { JSON_NUMBER } from '../wire/jsonNumber'
import { toWithdrawalDetail, toWithdrawalDetails } from '../wire/withdrawalPayload'
import { readPage } from './pagination'
import { append, appendEnum, appendEnums, appendString, appendUuid } from './queryParameters'
import { readResource } from './resourceRequest'
import { postSignedResource, type DaaUserSigning } from './signedResource'

/**
 * `GET /v1/accounts/withdrawals[/{withdrawalId}]` — the **public** path,
 * exactly as for Transfers (`TransfersClient.ts`).
 */
const WITHDRAWAL_PATH_PREFIX = '/v1/accounts/withdrawals/'
const WITHDRAWAL_COLLECTION_PATH = '/v1/accounts/withdrawals'

/** The closed set of withdrawal list statuses; mirrors `models/Withdrawal.ts`'s `WithdrawalStatus` kinds. */
const WITHDRAWAL_LIST_STATUSES = Object.freeze(['pending', 'complete', 'failed'] as const)

export type WithdrawalListQuery = Readonly<{
  /** Select a backing source explicitly; omitted derives from `accountId` or defaults to omnibus. */
  custodyType?: 'omnibus' | 'segregated' | 'self'
  /** Match withdrawals funded from this source account. Account ids are strings, not necessarily UUIDs. */
  accountId?: string
  /** Match any of these withdrawal statuses. Repeatable `status` query params. */
  status?: readonly (typeof WITHDRAWAL_LIST_STATUSES)[number][]
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
 * The properties the Owner-authorization registry's `withdrawal` schema names,
 * in the order it names them, at each level of the body. See
 * `TransfersClient`'s equivalent constant for why order matters: these are the
 * bytes that get signed.
 */
const WITHDRAWAL_PROPERTIES = Object.freeze([
  'idempotencyKey',
  'source',
  'destination',
  'amount',
  'toAmount',
  'riskSignals',
  'burnAll',
])
const WITHDRAWAL_SOURCE_PROPERTIES = Object.freeze(['type', 'id'])
const WITHDRAWAL_DESTINATION_PROPERTIES = Object.freeze(['type', 'id', 'name'])
const WITHDRAWAL_AMOUNT_PROPERTIES = Object.freeze(['amount', 'currency'])
const WITHDRAWAL_TO_AMOUNT_PROPERTIES = Object.freeze(['amount', 'currency'])
const WITHDRAWAL_RISK_SIGNAL_PROPERTIES = Object.freeze(['ipAddress', 'sessionId', 'deviceId'])
const WITHDRAWAL_TO_AMOUNT_CURRENCIES = Object.freeze(['USD', 'EUR'])

/**
 * Reads over DAA withdrawals, plus the signed withdrawal create, as the SDK
 * contract's `WithdrawalsClient`.
 *
 * {@link list} retains the API's RFC 8288 navigation queries as opaque text.
 * Collection rows use the same public projection {@link get} uses;
 * `policyEvaluation` is GET-only and is omitted (decoded as `null`) on list
 * items. {@link create} is an Owner-authorized write: it carries an
 * `X-Device-Authorization` bound to the exact bytes it sends and cannot happen
 * without the registered AuthKey `forUser` supplies.
 *
 * Not constructible by a consumer: exported from `index.ts` as a type only, and
 * the `#transport` field makes the type nominal.
 */
export class WithdrawalsClient {
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

  /** List withdrawals and retain the API's opaque navigation queries unchanged. */
  async list(query?: WithdrawalListQuery): Promise<Page<WithdrawalDetail>> {
    return readPage({
      transport: this.#transport,
      publicApiOrigin: this.#publicApiOrigin,
      path: WITHDRAWAL_COLLECTION_PATH,
      query: withdrawalListQuery(query),
      decode: toWithdrawalDetails,
    })
  }

  /** Read one withdrawal over the public Accounts route. */
  async get(withdrawalId: string): Promise<WithdrawalDetail> {
    if (!isUuid(withdrawalId)) {
      throw contractViolation('withdrawalId must be a UUID')
    }

    return readResource({
      transport: this.#transport,
      path: WITHDRAWAL_PATH_PREFIX + withdrawalId,
      decode: toWithdrawalDetail,
    })
  }

  /**
   * Create a withdrawal, authorized by the registered device key.
   *
   * The body is validated, serialized **once**, and that exact byte slice is
   * both hashed into the authorization's `body_sha256` claim and sent as the
   * request entity. Nothing between here and the transport re-serializes it.
   *
   * Neither the method nor the path is chosen here. `postSignedResource`
   * resolves both from the registry entry for `withdrawal`, so a signed write
   * cannot be aimed somewhere the operation does not name.
   *
   * The response decodes through the same public projection {@link get} uses:
   * `policyEvaluation` is GET-only and is omitted (decoded as `null`) here too.
   *
   * @throws DaaError with `detail.kind === 'contract_violation'` for a request
   *   the registry schema would reject, for an AuthKey that is not yet
   *   registered — the create is refused locally, before anything is signed or
   *   sent — for a rejected or replayed authorization (including a key that is
   *   no longer active: DAA has no revoked-credential code, so this never
   *   throws `device_revoked`), and for a response the SDK cannot read;
   *   `idempotency_conflict`, with the request's key, for a `409` with
   *   `IDEMPOTENCY_KEY_REUSED` (`420034`): reconcile the original withdrawal with
   *   the same key; do not mint a new key for it;
   *   `detail.kind === 'api'` for a status other than the documented `201`; and
   *   `detail.kind === 'transport'` if the consumer's transport throws, with the
   *   thrown value as `err.cause` and the request's `idempotencyKey` on the
   *   detail.
   */
  async create(request: CreateWithdrawalRequest): Promise<WithdrawalDetail> {
    const bodyBytes = serializeBody(createWithdrawalBody(request))
    return postSignedResource({
      transport: this.#transport,
      operation: 'withdrawal',
      authKey: await this.#signing.resolveAuthKey(),
      authKeyId: this.#signing.authKeyId,
      bodyBytes,
      // The contract documents exactly 201, with a Location header. Another
      // 2xx is an observable API failure rather than a silently accepted
      // variant, the same rule the by-id read applies to 200.
      expectedStatus: 201,
      decode: toWithdrawalDetail,
    })
  }
}

/**
 * Project a validated request onto the registry's `withdrawal` shape.
 *
 * Returned rather than serialized here so the caller can hold the one byte
 * slice this body becomes; see {@link WithdrawalsClient.create}.
 */
function createWithdrawalBody(request: CreateWithdrawalRequest): object {
  requireBodyObject(request, 'withdrawal create request')
  requireKnownProperties(request, WITHDRAWAL_PROPERTIES, 'withdrawal create request')

  const { idempotencyKey, source, destination, amount, toAmount, riskSignals, burnAll } = request

  // The registry types this `format: uuid` and, like `transfer`, narrows it no
  // further — unlike `create_account`, whose own contract text says v4.
  if (typeof idempotencyKey !== 'string' || !isUuid(idempotencyKey)) {
    throw contractViolation('idempotencyKey must be a UUID')
  }

  return {
    idempotencyKey,
    ...(source === undefined ? {} : { source: withdrawalSource(source) }),
    destination: withdrawalDestination(destination),
    amount: withdrawalAmount(amount),
    ...(toAmount === undefined ? {} : { toAmount: withdrawalToAmount(toAmount) }),
    ...(riskSignals === undefined ? {} : { riskSignals: withdrawalRiskSignals(riskSignals) }),
    ...(burnAll === undefined ? {} : { burnAll: withdrawalBurnAll(burnAll) }),
  }
}

function withdrawalSource(source: CreateWithdrawalSource): object {
  requireBodyObject(source, 'withdrawal source')
  requireKnownProperties(source, WITHDRAWAL_SOURCE_PROPERTIES, 'withdrawal source')
  const { type, id } = source
  if (type !== 'account') {
    throw contractViolation('withdrawal source type must be account')
  }
  if (typeof id !== 'string' || id.length === 0) {
    throw contractViolation('withdrawal source id must be a non-empty string')
  }
  return { type, id }
}

function withdrawalDestination(destination: CreateWithdrawalDestination): object {
  requireBodyObject(destination, 'withdrawal destination')
  requireKnownProperties(destination, WITHDRAWAL_DESTINATION_PROPERTIES, 'withdrawal destination')
  const { type, id, name } = destination
  if (type !== 'wire' && type !== 'ach') {
    throw contractViolation('withdrawal destination type must be wire or ach')
  }
  // Unlike a transfer's account-leg id, the registry types this `format: uuid`:
  // a withdrawal destination names a registered fiat account, not a public
  // account id.
  if (typeof id !== 'string' || !isUuid(id)) {
    throw contractViolation('withdrawal destination id must be a UUID')
  }
  if (name !== undefined && (typeof name !== 'string' || name.length === 0)) {
    throw contractViolation('withdrawal destination name must be a non-empty string')
  }
  return {
    type,
    id,
    ...(name === undefined ? {} : { name }),
  }
}

function withdrawalAmount(amount: CreateWithdrawalAmount): object {
  requireBodyObject(amount, 'withdrawal amount')
  requireKnownProperties(amount, WITHDRAWAL_AMOUNT_PROPERTIES, 'withdrawal amount')
  const { amount: amountValue, currency } = amount
  if (typeof amountValue !== 'string' || !JSON_NUMBER.test(amountValue)) {
    throw contractViolation('withdrawal amount must be a decimal string, e.g. "10.25"')
  }
  if (typeof currency !== 'string' || currency.length === 0) {
    throw contractViolation('withdrawal amount currency must be a non-empty string')
  }
  return { amount: amountValue, currency }
}

function withdrawalToAmount(toAmount: CreateWithdrawalToAmount): object {
  requireBodyObject(toAmount, 'withdrawal toAmount')
  requireKnownProperties(toAmount, WITHDRAWAL_TO_AMOUNT_PROPERTIES, 'withdrawal toAmount')
  const { amount, currency } = toAmount
  if (amount !== undefined && (typeof amount !== 'string' || !JSON_NUMBER.test(amount))) {
    throw contractViolation('withdrawal toAmount amount must be a decimal string, e.g. "10.25"')
  }
  if (typeof currency !== 'string' || !WITHDRAWAL_TO_AMOUNT_CURRENCIES.includes(currency)) {
    throw contractViolation('withdrawal toAmount currency must be USD or EUR')
  }
  return {
    ...(amount === undefined ? {} : { amount }),
    currency,
  }
}

function withdrawalRiskSignals(riskSignals: CreateWithdrawalRiskSignals): object {
  requireBodyObject(riskSignals, 'withdrawal risk signals')
  requireKnownProperties(riskSignals, WITHDRAWAL_RISK_SIGNAL_PROPERTIES, 'withdrawal risk signals')
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
    throw contractViolation(`withdrawal risk signal ${name} must be a non-empty string`)
  }
}

function withdrawalBurnAll(value: boolean): boolean {
  if (typeof value !== 'boolean') {
    throw contractViolation('withdrawal burnAll must be a boolean')
  }
  return value
}

function withdrawalListQuery(query: WithdrawalListQuery | undefined): string | null {
  if (query === undefined) return null
  if (typeof query !== 'object' || query === null || Array.isArray(query)) {
    throw contractViolation('withdrawal list query must be an object')
  }
  if (query.pageAfter !== undefined && query.pageBefore !== undefined) {
    throw contractViolation('pageAfter and pageBefore cannot be used together')
  }
  if (query.status !== undefined && (!Array.isArray(query.status) || query.status.length === 0)) {
    throw contractViolation('status must be a non-empty array')
  }

  const parts: string[] = []
  appendEnum(parts, 'custodyType', query.custodyType, ['omnibus', 'segregated', 'self'])
  appendString(parts, 'accountId', query.accountId)
  appendEnums(parts, 'status', query.status, WITHDRAWAL_LIST_STATUSES)
  appendString(parts, 'from', query.from)
  appendString(parts, 'to', query.to)
  // Unlike account cursors, the service models withdrawal cursors as UUID
  // withdrawal ids — the same rule `get`'s `withdrawalId` guard applies.
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
