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

import { AuthClient } from './api/AuthClient'
import { createDaaUserClient, type DaaUserClient } from './api/DaaUserClient'
import { assertDeviceKeyPolicy, assertPublicApiOrigin, DAA_ENVIRONMENTS } from './config'
import type { DaaEnvironment, DaaSdkConfiguration, DeviceKeyPolicy } from './config'
import { contractViolation } from './errors'
import {
  assertAuthKeyMatchesContext,
  isActiveDaaUserContext,
  type DaaUserContext,
} from './models/DaaUserContext'
import {
  createOwnerAuthKeyResolver,
  type AppAuthKeyResolver,
} from './securekey/ownerAuthKeyResolver'
import { assertAppId } from './securekey/alias'
import { assertNativeModuleKeyPolicyIfPresent } from './securekey/resolveNativeBridge'
import type { DaaTransport } from './transport/DaaTransport'

/**
 * Root DAA client.
 *
 * `auth.prepareSocialLogin` starts the three-call login. Social Session and
 * Device Registration Complete live on the values that returns. `forUser`
 * opens the authenticated operations surface only for an `ACTIVE`
 * `DaaUserContext`.
 */
export class DaaClient {
  readonly #config: DaaSdkConfiguration
  /** The validated `publicApiOrigin`, or `undefined` for the environment's origin. */
  readonly #publicApiOrigin: string | undefined
  readonly #auth: AuthClient
  /**
   * One resolver for the installation AuthKey, shared by login and `forUser`.
   * Takes the Owner's `clientEntityId` per call rather than baking
   * one in, since this `DaaClient` may serve more than one Owner over its
   * lifetime.
   *
   * Held here rather than inside `AuthClient` because both need it and neither
   * may hand it to a consumer: `AuthClient` is reachable as `client.auth`, so an
   * `OwnerAuthKey` returned from a method on it would be a generic signing
   * surface. This field is `#`-private, so it is reachable from `forUser` and
   * from nowhere else.
   */
  readonly #authKeys: AppAuthKeyResolver

  constructor(config: DaaSdkConfiguration) {
    if (!config.appId) {
      throw new Error('DAA: appId is required')
    }
    if (!config.transport) {
      throw new Error('DAA: transport is required')
    }
    if (!(DAA_ENVIRONMENTS as readonly string[]).includes(config.environment)) {
      throw new Error(
        `DAA: unknown environment "${config.environment}"; expected one of ${DAA_ENVIRONMENTS.join(', ')}`,
      )
    }
    // The key-namespace limits, checked here rather than first on key
    // resolution: that runs after Social Session, so a bad appId would fail
    // only once the service had bound the end user. After the presence checks,
    // so a missing field is reported first.
    assertAppId(config.appId)
    const publicApiOrigin = assertPublicApiOrigin(config.environment, config.publicApiOrigin)
    const keyPolicy = assertDeviceKeyPolicy(config.keyPolicy)
    // When DaaSecureKey is present, fail closed if it declares a weaker policy
    // than the configured closed set. Absent (Node / Jest) is not a pass —
    // resolveNativeBridge() still checks on first AuthKey use.
    assertNativeModuleKeyPolicyIfPresent(keyPolicy)
    this.#config = Object.freeze({ ...config, keyPolicy })
    this.#publicApiOrigin = publicApiOrigin
    // Built eagerly, but it resolves nothing until something asks: the Expo
    // DaaSecureKey module is reached on first resolution, so constructing a
    // DaaClient still does not require it.
    this.#authKeys = createOwnerAuthKeyResolver(
      { appId: config.appId, environment: config.environment },
      null,
    )
    // Constructed eagerly. Prepare needs no AuthKey and no DaaSecureKey. The
    // Expo DaaRegistration module (CSPRNG, flow key, receipt signature
    // verification) is resolved on first prepare, not here — matching
    // randomBytes / randomUuidV4. A host missing that module fails closed at
    // login. Jest injects a fake. AuthKey selection is lazy on Social Session.
    this.#auth = new AuthClient({
      transport: config.transport,
      authKeys: this.#authKeys,
      environment: config.environment,
    })
  }

  get appId(): string {
    return this.#config.appId
  }

  get environment(): DaaEnvironment {
    return this.#config.environment
  }

  get transport(): DaaTransport {
    return this.#config.transport
  }

  get keyPolicy(): DeviceKeyPolicy {
    return this.#config.keyPolicy
  }

  /** Starts one social-login attempt (Prepare). */
  get auth(): AuthClient {
    return this.#auth
  }

  /**
   * The authenticated operations surface for one user.
   *
   * Opens only for an `ACTIVE` `DaaUserContext` decoded from Device Registration
   * Complete. A fabricated object, a `RECOVERY_PENDING` result, or a missing
   * context fail closed — they are not an Owner-bound credential.
   *
   * The context is carried into the surface rather than only checked at the
   * door. `deviceContext.authKeyId` is the `kid` every signed write's
   * `X-Device-Authorization` announces, and the AuthKey it names is re-resolved
   * by the `{appId, environment}` alias login already used, together with
   * THIS context's own `clientEntityId` — the key itself is
   * enclave-held and is not a field on a decoded server result. Validating the
   * context and then dropping it would leave this surface with no credential
   * to sign with at all.
   */
  forUser(context: DaaUserContext): DaaUserClient {
    if (!isActiveDaaUserContext(context)) {
      throw contractViolation(
        'forUser requires an ACTIVE DaaUserContext from Device Registration Complete',
      )
    }
    // Bound to this context's clientEntityId now, once, rather than passed
    // through: `DaaUserSigning.resolveAuthKey` is a zero-arg
    // `OwnerAuthKeyResolver` (api/signedResource.ts) because a resource client
    // has no Owner concept of its own — it only ever signs for the user this
    // `forUser` call already validated.
    const clientEntityId = context.clientEntityId
    return createDaaUserClient(
      this.#config.transport,
      this.#config.environment,
      {
        resolveAuthKey: async () => {
          const authKey = await this.#authKeys(clientEntityId)
          await assertAuthKeyMatchesContext(context, authKey)
          return authKey
        },
        authKeyId: context.deviceContext.authKeyId,
      },
      this.#publicApiOrigin,
    )
  }
}
