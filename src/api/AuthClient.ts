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
  newRegistrationCodeVerifier,
  registrationCodeChallengeS256,
} from '../auth/registrationCodeVerifier'
import {
  checkPrepareReceipt,
  pinnedPrepareReceiptTrustAnchor,
  type PrepareReceiptTrustAnchor,
} from '../auth/prepareReceipt'
import {
  defaultRegistrationFlowKeyProvider,
  releaseQuietly,
  type RegistrationFlowKeyProvider,
} from '../auth/RegistrationFlowKey'
import type { DaaEnvironment } from '../config'
import { fromBase64Url } from '../crypto/base64url'
import { p256JwkThumbprint } from '../crypto/jwkThumbprint'
import { randomUuidV4 } from '../crypto/random'
import { serializeBody } from '../crypto/serialization'
import { contractViolation, isDaaError, withRequestId } from '../errors'
import { PreparedSocialLogin } from '../models/PreparedSocialLogin'
import {
  createOwnerAuthKeyResolver,
  type AppAuthKeyResolver,
} from '../securekey/ownerAuthKeyResolver'
import type { AppKeyIdentity, OwnerAuthKey, SecureKeyStore } from '../securekey/SecureKey'
import type { DaaTransport } from '../transport/DaaTransport'
import { headerValueIgnoringCase } from '../transport/headers'
import { toSocialLoginRequest } from '../wire/socialLoginRequestPayload'
import { loginStepFailure } from './loginFailure'
import { decodeResourceResponse } from './resourceRequest'

/**
 * `POST /v1/accounts/auth/loginRequests` — the contract's `prepareSocialLogin`
 * operation, on the **public** path — the form a consumer's transport is
 * handed, as for every other client here.
 *
 * There is no `/social/` segment. The contract path is
 * `/v1/accounts/auth/loginRequests` (camelCase), and its sibling
 * Social Session call is `/v1/accounts/auth/sessions`.
 */
const PREPARE_SOCIAL_LOGIN_PATH = '/v1/accounts/auth/loginRequests'

/**
 * Uppercase provider key, matching `PrepareSocialLoginRequest.provider`
 * (`^[A-Z][A-Z0-9_]*$`, `maxLength: 64`). Providers are application-registry
 * keys such as `GOOGLE` or `APPLE`, not raw issuer URLs.
 */
const PROVIDER = /^[A-Z][A-Z0-9_]{0,63}$/

/**
 * Unpadded Base64URL of a 91-byte P-256 SPKI is always 122 characters, and the
 * contract pins `registrationFlowPublicKey` to exactly that length. The charset
 * is the one this SDK's Base64URL codec emits.
 */
const FLOW_PUBLIC_KEY = /^[A-Za-z0-9_-]{122}$/

/** `registrationCodeChallenge` is an unpadded Base64URL SHA-256 digest: 43 characters. */
const CODE_CHALLENGE = /^[A-Za-z0-9_-]{43}$/

/**
 * The social-login entry point: `AuthClient`.
 *
 * Login is split into three calls — Prepare, Social Session, Device
 * Registration Complete. Prepare lives here; Session and Complete live on the
 * values Prepare returns (`PreparedSocialLogin.completeSocialSession`,
 * `PendingDeviceRegistration.complete`).
 *
 * Prepare does not touch an AuthKey. AuthKey selection happens only after
 * the Social Session response, via the injected store (tests) or the native
 * store (production). Prepare does check the DAA-signed Prepare receipt, before
 * it returns anything to the application — see `prepareSocialLogin`.
 *
 * Not constructible by a consumer: exported from `index.ts` as a type only, and
 * the `#transport` field makes the type nominal.
 */
export class AuthClient {
  readonly #transport: DaaTransport
  readonly #registrationFlowKeys: RegistrationFlowKeyProvider
  readonly #authKeys: AppAuthKeyResolver
  readonly #environment: DaaEnvironment | null
  readonly #prepareReceiptTrustAnchor: PrepareReceiptTrustAnchor | null

  /** @internal Constructed only through `DaaClient`. */
  constructor(args: {
    transport: DaaTransport
    /**
     * Defaults to native `DaaRegistrationFlowKey` via the Expo module. Injectable
     * so tests can substitute; not reachable from `DaaSdkConfiguration`, so a
     * consumer cannot substitute the key that proves its own registration handoff.
     */
    registrationFlowKeys?: RegistrationFlowKeyProvider
    /**
     * AuthKey store used after Social Session. Tests inject `./testing`'s
     * in-memory store; production leaves this unset and the resolver builds
     * `NativeSecureKeyStore` on first selection, because `DaaClient`
     * construction does not require the Expo `DaaSecureKey` module.
     */
    secureKeys?: SecureKeyStore
    /**
     * The consumer's app-level identity (`appId`, `environment`) — NOT the full
     * `OwnerKeyIdentity`: the Owner (`clientEntityId`) is not known until Social
     * Session responds, so it is supplied per call rather than here. Required
     * before AuthKey selection.
     */
    identity?: AppKeyIdentity
    /**
     * The resolver `DaaClient` shares between login and `forUser`, so both reach
     * one store and one in-flight `resolveOrCreate` map for this identity.
     * Unset, this client builds its own from `identity`/`secureKeys` — which is
     * what a test constructing `AuthClient` directly wants, since it has no
     * second holder to share with.
     */
    authKeys?: AppAuthKeyResolver
    /**
     * The configured environment: selects the pinned Prepare-receipt trust
     * anchor and is the value the receipt's `environment` claim must name.
     * Falls back to `identity.environment`.
     */
    environment?: DaaEnvironment
    /**
     * Test-only override of the pinned receipt trust anchor. Not reachable from
     * `DaaSdkConfiguration`: a consumer cannot choose the key that vouches for
     * its own relay's responses.
     */
    prepareReceiptTrustAnchor?: PrepareReceiptTrustAnchor | null
  }) {
    this.#transport = args.transport
    this.#registrationFlowKeys = args.registrationFlowKeys ?? defaultRegistrationFlowKeyProvider()
    this.#authKeys =
      args.authKeys ?? createOwnerAuthKeyResolver(args.identity ?? null, args.secureKeys ?? null)
    this.#environment = args.environment ?? args.identity?.environment ?? null
    this.#prepareReceiptTrustAnchor =
      args.prepareReceiptTrustAnchor !== undefined
        ? args.prepareReceiptTrustAnchor
        : this.#environment === null
          ? null
          : pinnedPrepareReceiptTrustAnchor(this.#environment)
    Object.freeze(this)
  }

  /**
   * Start one social-login attempt.
   *
   * The SDK owns the body `idempotencyKey`. Each call mints a new one and
   * serializes the body once for that request; the key is kept on the returned
   * `PreparedSocialLogin` so an ambiguous in-process retry can resend identical
   * bytes. Durable persistence across a restart is not implemented — see
   * `models/PreparedSocialLogin.ts`.
   *
   * The Prepare receipt is checked before this resolves, so an application
   * never holds a nonce from a response that failed that check. With no trust
   * anchor pinned for the environment — every environment in this release —
   * the SDK does no receipt work: a receipt the service sends is ignored, login
   * proceeds as if none arrived, and `prepareReceiptJws` is null. With an
   * anchor pinned, the receipt is required and must verify. See
   * `checkPrepareReceipt` in
   * `auth/prepareReceipt.ts`.
   *
   * @throws DaaError with `detail.kind === 'prepare_receipt_invalid'` when an
   *   anchor is pinned and the receipt is missing, malformed, fails its
   *   signature or claim checks, has expired, or the platform verifier is
   *   missing or fails; `contract_violation` for a rejected provider, unusable
   *   local key material, a missing native DaaRegistration module, or a
   *   response the SDK cannot read;
   *   `login_request_expired` for `410`; `idempotency_conflict` for a `409`
   *   with `IDEMPOTENCY_KEY_REUSED` (`420034`); `contract_violation` with the
   *   correlation id for `LOGIN_REQUEST_CONSUMED` (`420039`); and `api` for any
   *   other status besides the documented `201`, including any other `409`.
   *   Whatever the consumer's transport throws is rethrown unchanged.
   */
  async prepareSocialLogin(input: { provider: string }): Promise<PreparedSocialLogin> {
    if (typeof input !== 'object' || input === null || Array.isArray(input)) {
      throw contractViolation('prepareSocialLogin input must be an object')
    }
    if (typeof input.provider !== 'string' || !PROVIDER.test(input.provider)) {
      throw contractViolation(
        'provider must be an uppercase identity-provider key of at most 64 characters',
      )
    }
    const provider = input.provider

    // Ordering: verifier and flow key exist BEFORE Prepare is sent.
    const registrationCodeVerifier = newRegistrationCodeVerifier()
    const registrationCodeChallenge = registrationCodeChallengeS256(registrationCodeVerifier)
    if (!CODE_CHALLENGE.test(registrationCodeChallenge)) {
      throw contractViolation(
        'registration code challenge must be a 43-character unpadded Base64URL SHA-256 digest',
      )
    }
    const registrationFlowKey = await this.#registrationFlowKeys.generate()
    try {
      const registrationFlowPublicKey = await registrationFlowKey.publicKeySpkiBase64Url()
      if (!FLOW_PUBLIC_KEY.test(registrationFlowPublicKey)) {
        throw contractViolation(
          'registration-flow public key must be a 122-character unpadded Base64URL P-256 SPKI',
        )
      }

      const idempotencyKey = newIdempotencyKey()
      // Serialized once. These are the bytes that go on the wire, and the bytes an
      // exact retry has to reproduce; nothing downstream re-serializes them.
      //
      // idempotencyKey + provider are required; challenge and flow key are
      // optional. The service rejects unknown members with `400`, so
      // `registrationCodeChallengeMethod` is not sent. Always send challenge +
      // flow key; hold the verifier for Complete.
      const bodyBytes = serializeBody({
        idempotencyKey,
        provider,
        registrationCodeChallenge,
        registrationFlowPublicKey,
      })
      const response = await this.#transport.send({
        method: 'POST',
        path: PREPARE_SOCIAL_LOGIN_PATH,
        query: null,
        headers: { 'Content-Type': 'application/json' },
        bodyBytes,
      })

      const failure = loginStepFailure(response, idempotencyKey)
      if (failure !== null) {
        throw failure
      }

      const prepared = decodeResourceResponse({
        response,
        expectedStatus: 201,
        decode: toSocialLoginRequest,
      })
      const verifiedReceipt = await checkPrepareReceipt(
        prepared.prepareReceiptJws,
        this.#prepareReceiptTrustAnchor,
        () => ({
          loginRequestId: prepared.loginRequestId,
          nonce: prepared.oidcNonce,
          provider,
          environment: this.#requireEnvironmentForReceipt(),
          // The SDK's own values, generated before Prepare was sent: the two a
          // relay substituting another attempt cannot make match.
          registrationCodeChallenge,
          registrationFlowKeyThumbprint: p256JwkThumbprint(
            fromBase64Url(registrationFlowPublicKey),
          ),
        }),
      ).catch((err: unknown) => {
        // A rejected receipt came from this response, so it names the
        // response's request id. A `contract_violation` from the check is this
        // SDK's own configuration fault and is left as it is.
        throw isDaaError(err) && err.detail.kind === 'prepare_receipt_invalid'
          ? withRequestId(err, headerValueIgnoringCase(response.headers, 'X-Request-Id'))
          : err
      })
      return new PreparedSocialLogin({
        loginRequestId: prepared.loginRequestId,
        oidcNonce: prepared.oidcNonce,
        oidcState: prepared.oidcState,
        // Only a receipt that verified; an ignored one is not handed on.
        prepareReceiptJws: verifiedReceipt === null ? null : verifiedReceipt.compactJws,
        expiresAt: prepared.expiresAt,
        registrationCodeVerifier,
        registrationFlowKey,
        idempotencyKey,
        transport: this.#transport,
        resolveAuthKey: (clientEntityId: string) => this.#resolveAuthKey(clientEntityId),
      })
    } catch (error) {
      // Keep the key on a successful PreparedSocialLogin — Complete still needs
      // the private half. A failed attempt has no holder, so drop the native
      // cache entry rather than leaking it for the process lifetime.
      await releaseQuietly(registrationFlowKey)
      throw error
    }
  }

  /**
   * Select or create the installation AuthKey only after Social Session.
   * Prepare never calls this.
   *
   * `clientEntityId` namespaces the key per Owner. The caller —
   * `PreparedSocialLogin.completeSocialSession` — passes the Social Session
   * response's OWN echo of `clientEntityId`, not the value the application
   * supplied to that call, because the response is the server-confirmed one.
   *
   * Private, and it stays private — with an ECMAScript `#` private field, not
   * TypeScript's `private` keyword, which is erased at build time and would
   * leave an ordinary callable method on the prototype. `AuthClient` is
   * reachable from a consumer as `DaaClient.auth`, so a merely
   * compile-time-private method here would hand out an `OwnerAuthKey` — and
   * with it `signExactBytes` — which is the generic signing surface this SDK
   * does not have. `forUser` reaches the same key through the resolver
   * `DaaClient` owns, not through this client.
   */
  async #resolveAuthKey(clientEntityId: string): Promise<OwnerAuthKey> {
    return this.#authKeys(clientEntityId)
  }

  /**
   * Reached only when a receipt is being verified against an anchor. A missing
   * environment is this SDK's own wiring fault, so it stays `contract_violation`.
   */
  #requireEnvironmentForReceipt(): DaaEnvironment {
    if (this.#environment === null) {
      throw contractViolation('verifying a Prepare receipt requires the configured environment')
    }
    return this.#environment
  }
}

function newIdempotencyKey(): string {
  return randomUuidV4()
}
