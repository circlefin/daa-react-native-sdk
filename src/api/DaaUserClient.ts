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

import { publicApiOriginFor } from '../config'
import type { DaaEnvironment } from '../config'
import { idempotencyKeyFromExactBody } from '../auth/deviceAuthorization'
import { contractViolation, DaaError, transportFailure } from '../errors'
import type { DeviceContext } from '../models/DaaUserContext'
import type { OwnerAuthKey } from '../securekey/SecureKey'
import type { DaaHttpRequest, DaaTransport } from '../transport/DaaTransport'
import { toDeviceContext } from '../wire/deviceContextPayload'
import { AccountLimitsClient } from './AccountLimitsClient'
import { AccountsClient } from './AccountsClient'
import { DepositAddressesClient } from './DepositAddressesClient'
import { DepositsClient } from './DepositsClient'
import { FiatAccountsClient } from './FiatAccountsClient'
import { getSignedResource, type DaaUserSigning } from './signedResource'
import { TransactionsClient } from './TransactionsClient'
import { TransfersClient } from './TransfersClient'
import { WithdrawalsClient } from './WithdrawalsClient'

/**
 * The authenticated operations surface, as the SDK contract's `DaaUserClient`.
 *
 * The contract reaches this through the root client's `forUser(context)`, and every
 * operation lives here rather than on the root client — the root client has only
 * `auth` and `forUser`.
 *
 * Every resource client here has at least one operation; the surface never
 * exposes a client with none.
 *
 * Signing material reaches only the clients that have a signed operation.
 * Account limits, deposits, deposit addresses, transactions, and fiat
 * accounts read (and, for deposit addresses, write unsigned) and so are
 * handed none — a client that cannot sign cannot be made to sign by a later
 * edit that forgets which calls are authorized. Fiat-account reads and
 * get-instructions are both unsigned operations; for account limits/usage,
 * see `AccountLimitsClient`'s class note for why it is unsigned.
 */
export class DaaUserClient {
  /** Reads over DAA accounts, and the signed account create. */
  readonly accounts: AccountsClient
  /** Reads over an account's limits and current usage. */
  readonly accountLimits: AccountLimitsClient
  /** Reads over DAA deposit addresses. */
  readonly depositAddresses: DepositAddressesClient
  /** Reads over DAA deposits, and the paged deposit list. */
  readonly deposits: DepositsClient
  /** Reads over DAA unified account activity. */
  readonly transactions: TransactionsClient
  /** Reads over DAA transfers, and the signed transfer create. */
  readonly transfers: TransfersClient
  /** Reads over DAA withdrawals, and the signed withdrawal create. */
  readonly withdrawals: WithdrawalsClient
  /** Reads over wire and ACH fiat accounts, and their receiving instructions. */
  readonly fiatAccounts: FiatAccountsClient

  readonly #transport: DaaTransport
  readonly #signing: DaaUserSigning
  readonly #markClosed: () => void

  /** @internal Constructed only through {@link createDaaUserClient}. */
  constructor(
    transport: DaaTransport,
    environment: DaaEnvironment,
    signing: DaaUserSigning,
    publicApiOriginOverride?: string,
  ) {
    const publicApiOrigin = publicApiOriginOverride ?? publicApiOriginFor(environment)

    // `close()` has to reach every signed operation this surface
    // exposes, not just `refreshContext` — an accounts/transfers/withdrawals
    // `create` reached through a "closed" client is exactly the further use
    // `close()` exists to refuse. Every signed client below is handed this one
    // wrapper rather than the caller's `signing` directly, so flipping `closed`
    // here closes all of them at once without editing any resource client.
    let closed = false
    const assertOpen = (): void => {
      if (closed) {
        throw contractViolation(
          'DaaUserClient is closed; call DaaClient.forUser again to resume operations',
        )
      }
    }
    const guardedSigning: DaaUserSigning = Object.freeze({
      authKeyId: signing.authKeyId,
      resolveAuthKey: async () => {
        assertOpen()
        return guardAuthKey(await signing.resolveAuthKey(), assertOpen)
      },
    })

    // The transport guard closes unsent unsigned work too: a retained Page's
    // next()/previous() closure still holds the client it was created from,
    // so handing every resource client this wrapper makes close() reach those
    // later sends without editing each pagination client.
    //
    // It is also the one place every operation on this surface reaches the
    // consumer's transport, so it is where a throw from that transport becomes
    // the SDK's `transport` error (see `transportFailure`). Only the send is
    // wrapped: a closed client's `contract_violation` is the SDK's own refusal,
    // not a transport failure, and is thrown before anything is sent.
    const guardedTransport: DaaTransport = Object.freeze({
      send: async (request: DaaHttpRequest) => {
        assertOpen()
        try {
          return await transport.send(request)
        } catch (err) {
          throw asTransportFailure(err, request)
        }
      },
    })

    this.accounts = new AccountsClient(guardedTransport, publicApiOrigin, guardedSigning)
    this.accountLimits = new AccountLimitsClient(guardedTransport)
    this.depositAddresses = new DepositAddressesClient(guardedTransport, publicApiOrigin)
    this.deposits = new DepositsClient(guardedTransport, publicApiOrigin)
    this.transactions = new TransactionsClient(guardedTransport, publicApiOrigin)
    this.transfers = new TransfersClient(guardedTransport, publicApiOrigin, guardedSigning)
    this.withdrawals = new WithdrawalsClient(guardedTransport, publicApiOrigin, guardedSigning)
    this.fiatAccounts = new FiatAccountsClient(guardedTransport)

    this.#transport = guardedTransport
    this.#signing = guardedSigning
    this.#markClosed = () => {
      closed = true
    }
    Object.freeze(this)
  }

  /**
   * Signed context refresh (`refreshContext`).
   *
   * `get_device_context` (`GET /v1/accounts/auth/context`) is a registered-device
   * authorization operation, not an ordinary unsigned read: the device
   * authorization payload applies to registered-device authorization for
   * protected writes and signed context refresh, alongside `transfer` and
   * `withdrawal`, and `securekey/SecureKey.ts` names "signed context refresh"
   * alongside "protected writes" as one of the defined DAA operations signing is
   * reachable for. There is no request body: `getSignedResource` signs over the
   * empty byte array per the bodyless-request rule and sends nothing as
   * the request entity.
   *
   * @throws DaaError with `detail.kind === 'contract_violation'` for an AuthKey
   *   that is not yet registered, for a rejected or replayed authorization
   *   (including a key that is no longer active: DAA has no revoked-credential
   *   code, so this never throws `device_revoked`), for a response the SDK
   *   cannot read, and once this client is {@link close}d;
   *   `detail.kind === 'api'` for a status other than the documented `200`; and
   *   `detail.kind === 'transport'` if the consumer's transport throws, with
   *   the thrown value as `err.cause`.
   */
  async refreshContext(): Promise<DeviceContext> {
    return getSignedResource({
      transport: this.#transport,
      operation: 'get_device_context',
      authKey: await this.#signing.resolveAuthKey(),
      authKeyId: this.#signing.authKeyId,
      expectedStatus: 200,
      decode: toDeviceContext,
    })
  }

  /**
   * `DaaUserClient.close()` clears active context from memory and cancels
   * unsent work. It preserves an active profile-scoped AuthKey and credential;
   * application logout is not device revocation.
   *
   * This class holds no `DaaUserContext` object and no cancellable in-flight
   * work of its own to release — the context a caller passed to `forUser` is
   * never retained here, only the plain `authKeyId` string and a resolver
   * closure, and every call this SDK makes is a single `transport.send` awaited
   * to completion with no cancellation token in the transport contract to
   * cancel. Concretely, close() revokes this instance's own capability to
   * produce a fresh `X-Device-Authorization` at all, so `refreshContext` and
   * every signed `create` on `accounts` / `transfers` / `withdrawals` fail
   * closed with `contract_violation` from this point on instead of silently
   * continuing to sign. The guarded transport also refuses unsigned reads, writes, and
   * retained Page navigation closures after close, so unsent work cannot
   * outlive the user surface that created it. The registered AuthKey and
   * Circle's registration acknowledgement are untouched — nothing here calls
   * the native store, so there is nothing here that could revoke either.
   * Idempotent: closing an already-closed client is a no-op.
   */
  close(): void {
    this.#markClosed()
  }
}

/**
 * Keep an in-flight signed operation tied to this user's lifecycle. The
 * resolver guard prevents new operations after `close()`, while the signing
 * guard also covers an operation that started before `close()` and would
 * otherwise sign with the already-resolved AuthKey.
 */
function guardAuthKey(authKey: OwnerAuthKey, assertOpen: () => void): OwnerAuthKey {
  return Object.freeze({
    publicKeySpkiBase64Url: () => authKey.publicKeySpkiBase64Url(),
    thumbprint: () => authKey.thumbprint(),
    resolution: () => authKey.resolution(),
    acknowledgeRegistration: () => authKey.acknowledgeRegistration(),
    signExactBytes: async (message: Uint8Array) => {
      assertOpen()
      return authKey.signExactBytes(message)
    },
    signRegistrationDeviceAuthorization: async (message: Uint8Array) => {
      assertOpen()
      return authKey.signRegistrationDeviceAuthorization(message)
    },
  })
}

/**
 * Build the operations surface over a transport.
 *
 * Deliberately **not** exported from `index.ts`, and deliberately not a member of
 * `DaaClient`: a consumer must not reach this without the user context that
 * `forUser` requires, decoded from an `ACTIVE` Device Registration Complete.
 *
 * `publicApiOrigin` is the override `DaaClient` has already validated. Without
 * it, the environment's public API origin is the pagination trust anchor.
 */
export function createDaaUserClient(
  transport: DaaTransport,
  environment: DaaEnvironment,
  signing: DaaUserSigning,
  publicApiOrigin?: string,
): DaaUserClient {
  return new DaaUserClient(transport, environment, signing, publicApiOrigin)
}

/**
 * Wrap a throw from the consumer's transport as a `transport` error. An error
 * that is already a `DaaError` passes through unchanged, as in
 * `mapNativeError`.
 *
 * The idempotency key is read from the exact bytes that were handed to the
 * transport, with the same reader the signed `409` mapping uses. A body the
 * reader cannot parse leaves the key off rather than replacing the transport
 * failure with a different error.
 */
function asTransportFailure(err: unknown, request: DaaHttpRequest): DaaError {
  if (err instanceof DaaError) {
    return err
  }
  let idempotencyKey: string | undefined
  if (request.bodyBytes !== null) {
    try {
      idempotencyKey = idempotencyKeyFromExactBody(request.bodyBytes)
    } catch {
      idempotencyKey = undefined
    }
  }
  return transportFailure(err, idempotencyKey)
}
