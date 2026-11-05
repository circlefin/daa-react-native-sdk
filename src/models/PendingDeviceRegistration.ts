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

import {
  authorizeRegistrationComplete,
  DEVICE_REGISTRATION_COMPLETE_PATH,
  REGISTRATION_DEVICE_AUTHORIZATION_HEADER,
  REGISTRATION_FLOW_AUTHORIZATION_HEADER,
} from '../auth/registrationAuthorization'
import { releaseQuietly, type RegistrationFlowKey } from '../auth/RegistrationFlowKey'
import { randomUuidV4 } from '../crypto/random'
import { serializeBody } from '../crypto/serialization'
import { contractViolation } from '../errors'
import type { OwnerAuthKey } from '../securekey/SecureKey'
import type { DaaTransport } from '../transport/DaaTransport'
import { loginStepFailure } from '../api/loginFailure'
import { decodeResourceResponse } from '../api/resourceRequest'
import { toDeviceRegistrationResult } from '../wire/deviceRegistrationResultPayload'
import { bindAuthKeyToContext, type DeviceRegistrationResult } from './DaaUserContext'

const AUTH_KEY_PUBLIC_KEY = /^[A-Za-z0-9_-]{122}$/

/**
 * Pending device registration after Social Session.
 *
 * `complete()` is Device Registration Complete: the four-field body
 * (`idempotencyKey`, `registrationHandle`, `registrationCodeVerifier`,
 * `authKeyPublicKey`), including the registration code verifier minted before
 * Prepare and redeemed here against the challenge Prepare sent. Two JWSs
 * authorize it — `X-Device-Authorization` (signed by the proposed AuthKey) and
 * `X-Registration-Flow-Authorization` (signed by the per-attempt flow key from
 * Prepare) — both over the exact body bytes. Both carry the same request claims
 * bar `jti`; only the flow proof also carries the binding claims (registration
 * handle, profile, AuthKey thumbprint, code verifier). Building and signing
 * those proofs is `authorizeRegistrationComplete`.
 *
 * Every device takes this same path, first or additional. A new device on an
 * existing Owner does social login and then this same registration, with the
 * same body; there is no approval from an already-registered device and
 * no mode to select. DAA adds the new AuthKey next to the Owner's existing
 * keys (additive registration).
 *
 * There is no `abandon()`. If the caller backs out after Session without
 * calling `complete()`, the native flow-key cache is held until the process
 * exits; `complete()` releases it in `finally`. The API has no cancel call for
 * a pending registration.
 *
 * Not constructible by a consumer: exported from `index.ts` as a type only.
 */
export class PendingDeviceRegistration {
  readonly registrationHandle: string
  readonly clientEntityId: string
  /**
   * When the registration handle expires, as ISO-8601 text. The decoder also
   * accepts the epoch-millisecond form the service sends for this timestamp
   * and normalises it here, so a consumer never sees the wire's disagreement.
   */
  readonly expiresAt: string

  readonly #transport: DaaTransport
  readonly #registrationCodeVerifier: string
  readonly #registrationFlowKey: RegistrationFlowKey
  readonly #authKey: OwnerAuthKey
  #consumed = false

  /** @internal Constructed only by `PreparedSocialLogin.completeSocialSession`. */
  constructor(fields: {
    readonly registrationHandle: string
    readonly clientEntityId: string
    readonly expiresAt: string
    readonly transport: DaaTransport
    readonly registrationCodeVerifier: string
    readonly registrationFlowKey: RegistrationFlowKey
    readonly authKey: OwnerAuthKey
  }) {
    this.registrationHandle = fields.registrationHandle
    this.clientEntityId = fields.clientEntityId
    this.expiresAt = fields.expiresAt
    this.#transport = fields.transport
    this.#registrationCodeVerifier = fields.registrationCodeVerifier
    this.#registrationFlowKey = fields.registrationFlowKey
    this.#authKey = fields.authKey
    Object.freeze(this)
  }

  /**
   * Finish the ceremony: `POST /v1/accounts/auth/deviceKeyRegistration` with
   * both `X-Device-Authorization` and `X-Registration-Flow-Authorization`
   * bound to the exact body bytes.
   *
   * Takes no input: the body is the same four fields for every device — see
   * the class doc.
   *
   * The service returns a flat `DeviceContext`. A `{ status, context }` /
   * `RECOVERY_PENDING` payload is also decoded. On `ACTIVE`, acknowledges
   * the AuthKey so later `resolveOrCreate` returns `existing`.
   *
   * @throws DaaError with `detail.kind === 'login_request_expired'` for `410`;
   *   `idempotency_conflict` for a `409` with `IDEMPOTENCY_KEY_REUSED`
   *   (`420034`); `contract_violation` for `LOGIN_REQUEST_CONSUMED` (`420039`),
   *   for a second call, for unusable key material, and for a response the SDK
   *   cannot read; and `api` for any other status besides the documented
   *   `200`, including the `409` that DAA sends with `AUTH_KEY_BINDING_CONFLICT`
   *   (`420038`).
   */
  async complete(): Promise<DeviceRegistrationResult> {
    if (this.#consumed) {
      throw contractViolation('this pending device registration has already been consumed')
    }
    this.#consumed = true

    try {
      const authKeyPublicKey = await this.#authKey.publicKeySpkiBase64Url()
      if (!AUTH_KEY_PUBLIC_KEY.test(authKeyPublicKey)) {
        throw contractViolation(
          'AuthKey public key must be a 122-character unpadded Base64URL P-256 SPKI',
        )
      }

      const idempotencyKey = randomUuidV4()
      const bodyBytes = serializeBody({
        idempotencyKey,
        registrationHandle: this.registrationHandle,
        registrationCodeVerifier: this.#registrationCodeVerifier,
        authKeyPublicKey,
      })
      const { deviceJws, flowJws } = await authorizeRegistrationComplete({
        bodyBytes,
        registrationHandle: this.registrationHandle,
        registrationCodeVerifier: this.#registrationCodeVerifier,
        clientEntityId: this.clientEntityId,
        flowKey: this.#registrationFlowKey,
        authKey: this.#authKey,
      })

      const response = await this.#transport.send({
        method: 'POST',
        path: DEVICE_REGISTRATION_COMPLETE_PATH,
        query: null,
        headers: {
          'Content-Type': 'application/json',
          [REGISTRATION_DEVICE_AUTHORIZATION_HEADER]: deviceJws,
          [REGISTRATION_FLOW_AUTHORIZATION_HEADER]: flowJws,
        },
        bodyBytes,
      })

      const failure = loginStepFailure(response, idempotencyKey)
      if (failure !== null) {
        throw failure
      }

      const result = decodeResourceResponse({
        response,
        expectedStatus: 200,
        decode: (value) => toDeviceRegistrationResult(value, this.clientEntityId),
      })
      return await this.#finish(result)
    } finally {
      await releaseQuietly(this.#registrationFlowKey)
    }
  }

  async #finish(result: DeviceRegistrationResult): Promise<DeviceRegistrationResult> {
    switch (result.status) {
      case 'ACTIVE':
        // Keep the server-assigned authKeyId as the JWS kid, but retain the
        // local key's thumbprint alongside it. `DaaClient.forUser` checks this
        // pairing every time it resolves the key for a signed operation.
        const boundContext = bindAuthKeyToContext(result.context, await this.#authKey.thumbprint())
        await this.#authKey.acknowledgeRegistration()
        return Object.freeze({ ...result, context: boundContext })
      case 'RECOVERY_PENDING':
        return result
      default: {
        const exhaustive: never = result
        void exhaustive
        throw contractViolation('device registration status is not in the closed set')
      }
    }
  }
}
