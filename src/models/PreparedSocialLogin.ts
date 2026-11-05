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

import { requireOwnerGrantFlowKeyThumbprint } from '../auth/ownerGrant'
import { releaseQuietly, type RegistrationFlowKey } from '../auth/RegistrationFlowKey'
import { fromBase64Url } from '../crypto/base64url'
import { p256JwkThumbprint } from '../crypto/jwkThumbprint'
import { randomUuidV4 } from '../crypto/random'
import { serializeBody } from '../crypto/serialization'
import { contractViolation } from '../errors'
import type { OwnerAuthKey } from '../securekey/SecureKey'
import type { DaaTransport } from '../transport/DaaTransport'
import { headerValueIgnoringCase } from '../transport/headers'
import { isUuid } from '../validation/uuid'
import { loginStepFailure } from '../api/loginFailure'
import { decodeResourceResponse } from '../api/resourceRequest'
import { toPendingRegistration } from '../wire/pendingRegistrationPayload'
import { PendingDeviceRegistration } from './PendingDeviceRegistration'

/**
 * `POST /v1/accounts/auth/sessions` — the contract's `completeSocialLogin`
 * operation, on the public path.
 */
export const SOCIAL_SESSION_PATH = '/v1/accounts/auth/sessions'

const ID_TOKEN_MAX_LENGTH = 16384

/**
 * A prepared social login: `PreparedSocialLogin`.
 *
 * The five public fields are what the consuming application carries through its
 * own provider login. There is deliberately no AuthKey field of any kind — no
 * `authKeyId`, no thumbprint — because AuthKey selection happens *after* the
 * Social Session response, so at this point in the flow no AuthKey has been
 * chosen and naming one would be fiction.
 *
 * Held privately, for one attempt only:
 *
 * - the **registration code verifier**, whose S256 challenge went out at Prepare
 *   and whose digest is redeemed in the Complete flow-proof claim set;
 * - the **ephemeral registration-flow key**. It signs the
 *   `X-Registration-Flow-Authorization` proof sent on Complete. Not an
 *   AuthKey — see `auth/RegistrationFlowKey.ts`;
 * - the Prepare **`idempotencyKey`**, so an ambiguous retry can resend identical
 *   bytes rather than starting a second logical attempt.
 *
 * All three are `#` private fields. The verifier in particular is the secret that
 * binds the two halves of the handoff; it is never a public field, never in an
 * error message, and never logged.
 *
 * **This state lives in memory, for the life of this object.** It is not
 * persisted across a process restart. A login attempt that does not
 * survive to `completeSocialSession` is abandoned, and a new Prepare starts a
 * new attempt with fresh material — the fail-closed behaviour. Call
 * {@link PreparedSocialLogin.abandon} when the user backs out so the native
 * flow-key cache is dropped; dropping this object alone does not.
 *
 * `AuthClient.prepareSocialLogin` checks the Prepare receipt before it
 * constructs this object (`auth/prepareReceipt.ts`, `checkPrepareReceipt`), so
 * an instance only exists for a response that passed that check. Session does
 * not consume receipt claims: it sends `loginRequestId` plus the application's
 * `idToken` and `clientEntityId`.
 *
 * Not constructible by a consumer: exported from `index.ts` as a type only, and
 * the `#` private fields make the type nominal.
 */
export class PreparedSocialLogin {
  /** Opaque, single-use DAA correlation for this pending registration attempt. */
  readonly loginRequestId: string

  /**
   * Single-use nonce the application supplies to the social provider. Only a
   * verified receipt's `nonce` claim binds it to `loginRequestId`, and no
   * receipt trust anchor is pinned in this release, so it is unauthenticated
   * relay output. Do not treat it as proof that the login request came from
   * Circle: bind the login with the application's own OAuth `state` and its
   * authenticated session with its backend.
   */
  readonly oidcNonce: string

  /**
   * DAA correlation to bind inside or alongside the application's own OAuth
   * CSRF state. Per the contract it "must not replace app-owned redirect
   * protection". The receipt does not bind it: DAA signs no state claim, so it
   * is unauthenticated whether or not a trust anchor is pinned. The
   * application's own `state` is the primary binding for the provider redirect.
   */
  readonly oidcState: string

  /**
   * The DAA-signed Prepare receipt, verified before this object exists. Null
   * when no trust anchor is pinned for the environment, which is every
   * environment in this release: the SDK then ignores any receipt the service
   * sends, and does not hand on one it has not checked.
   */
  readonly prepareReceiptJws: string | null

  /**
   * When the login request expires, as ISO-8601 text. The contract declares that
   * string form and the running service sends epoch milliseconds, so the decoder
   * accepts both and normalises the number to this one representation — a
   * consumer never sees the wire's disagreement.
   */
  readonly expiresAt: string

  readonly #registrationCodeVerifier: string
  readonly #registrationFlowKey: RegistrationFlowKey
  readonly #idempotencyKey: string
  readonly #transport: DaaTransport
  readonly #resolveAuthKey: (clientEntityId: string) => Promise<OwnerAuthKey>
  #sessionConsumed = false

  /** @internal Constructed only by `AuthClient.prepareSocialLogin`. */
  constructor(fields: {
    readonly loginRequestId: string
    readonly oidcNonce: string
    readonly oidcState: string
    readonly prepareReceiptJws: string | null
    readonly expiresAt: string
    readonly registrationCodeVerifier: string
    readonly registrationFlowKey: RegistrationFlowKey
    readonly idempotencyKey: string
    readonly transport: DaaTransport
    readonly resolveAuthKey: (clientEntityId: string) => Promise<OwnerAuthKey>
  }) {
    this.loginRequestId = fields.loginRequestId
    this.oidcNonce = fields.oidcNonce
    this.oidcState = fields.oidcState
    this.prepareReceiptJws = fields.prepareReceiptJws
    this.expiresAt = fields.expiresAt
    this.#registrationCodeVerifier = fields.registrationCodeVerifier
    this.#registrationFlowKey = fields.registrationFlowKey
    this.#idempotencyKey = fields.idempotencyKey
    this.#transport = fields.transport
    this.#resolveAuthKey = fields.resolveAuthKey
    Object.freeze(this)
  }

  /**
   * Exchange the provider ID token for a pending device registration:
   * `POST /v1/accounts/auth/sessions` (the Social Session call).
   *
   * AuthKey selection happens only after a successful response, then the
   * returned `PendingDeviceRegistration` can call Device Registration Complete.
   *
   * `clientEntityId` is required, and there is no resolve-or-create fallback
   * behind it: the service refuses a Session that omits it. The value names an
   * end user the application's own backend has already onboarded to an active
   * account — Circle never creates one here. The service checks that the entity
   * belongs to the authenticated parent and then binds this end user to it
   * permanently, so a wrong id is not a mistake a later call can undo.
   *
   * It is taken on this method because this is the call that carries it. Taking
   * it at client construction would pin one end user to a whole `DaaClient`, and
   * taking it at Prepare would pin it to an attempt that has not yet named one.
   *
   * The `idToken` is sent in the exact body bytes and is never logged, stored on
   * this object, or interpolated into errors.
   *
   * @throws DaaError with `detail.kind === 'login_request_expired'` for `410`;
   *   `idempotency_conflict` for a `409` with `IDEMPOTENCY_KEY_REUSED`
   *   (`420034`); `contract_violation` for invalid input, a second call,
   *   `LOGIN_REQUEST_CONSUMED` (`420039`), a response the SDK cannot read, and
   *   an Owner grant that is not bound to this attempt's flow key; and `api`
   *   for any other status besides the documented `200`, including any other
   *   `409`.
   */
  async completeSocialSession(input: {
    idToken: string
    clientEntityId: string
  }): Promise<PendingDeviceRegistration> {
    if (typeof input !== 'object' || input === null || Array.isArray(input)) {
      throw contractViolation('completeSocialSession input must be an object')
    }
    if (
      typeof input.idToken !== 'string' ||
      input.idToken.length < 1 ||
      input.idToken.length > ID_TOKEN_MAX_LENGTH
    ) {
      throw contractViolation('idToken must be a provider token of at most 16384 characters')
    }
    if (typeof input.clientEntityId !== 'string' || !isUuid(input.clientEntityId)) {
      throw contractViolation('clientEntityId must be a UUID')
    }
    if (this.#sessionConsumed) {
      throw contractViolation('this prepared social login has already been consumed')
    }

    const idToken = input.idToken
    const clientEntityId = input.clientEntityId
    // One-shot on this object: latch before send. A dropped connection still
    // consumes the attempt; recovery is a new `prepareSocialLogin`, not a retry
    // of `completeSocialSession` (the verifier and flow key are bound here).
    this.#sessionConsumed = true
    try {
      // Prepare's idempotency key is for Prepare retries only. Session is a
      // distinct operation and owns its own key.
      void this.#idempotencyKey
      const idempotencyKey = randomUuidV4()
      // Serialized once. These are the bytes that go on the wire; nothing
      // downstream re-serializes them. The four members are the service's four
      // required properties, in the order it declares them.
      const bodyBytes = serializeBody({
        idempotencyKey,
        loginRequestId: this.loginRequestId,
        idToken,
        clientEntityId,
      })
      const response = await this.#transport.send({
        method: 'POST',
        path: SOCIAL_SESSION_PATH,
        query: null,
        headers: { 'Content-Type': 'application/json' },
        bodyBytes,
      })

      const failure = loginStepFailure(response, idempotencyKey)
      if (failure !== null) {
        throw failure
      }

      const pending = decodeResourceResponse({
        response,
        expectedStatus: 200,
        decode: toPendingRegistration,
      })

      if (pending.ownerGrant !== null) {
        const flowSpki = fromBase64Url(await this.#registrationFlowKey.publicKeySpkiBase64Url())
        requireOwnerGrantFlowKeyThumbprint(
          pending.ownerGrant,
          p256JwkThumbprint(flowSpki),
          headerValueIgnoringCase(response.headers, 'X-Request-Id'),
        )
      }

      // Select or create the AuthKey only after the Social Session response.
      // Namespaced to `pending.clientEntityId` — the response's OWN echo of the
      // bound entity — and NOT `clientEntityId` (this method's argument),
      // because the service is what validates and binds that value; it is the
      // server-confirmed identity the rest of the ceremony, and every later
      // `forUser` re-resolution, is checked against.
      const authKey = await this.#resolveAuthKey(pending.clientEntityId)
      return new PendingDeviceRegistration({
        registrationHandle: pending.registrationHandle,
        // The service's own echo of the bound entity, decoded from the response,
        // not the argument this method was handed. The response field is what the
        // rest of the ceremony is checked against, so it stays the one source.
        clientEntityId: pending.clientEntityId,
        expiresAt: pending.expiresAt,
        transport: this.#transport,
        registrationCodeVerifier: this.#registrationCodeVerifier,
        registrationFlowKey: this.#registrationFlowKey,
        authKey,
      })
    } catch (error) {
      await releaseQuietly(this.#registrationFlowKey)
      throw error
    }
  }

  /**
   * Drop the native registration-flow key for this attempt.
   *
   * Call this when the user backs out of provider login. The JS handle going out
   * of scope does not clear the native process cache. Safe to call more than
   * once. After this, the attempt cannot proceed to Registration Complete.
   */
  async abandon(): Promise<void> {
    await this.#registrationFlowKey.release()
  }
}
