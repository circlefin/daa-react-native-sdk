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

import type { DaaEnvironment } from '../config'

/**
 * The consumer's application-level identity: `appId` and `environment`, known
 * at `DaaClient`/`AuthClient` construction, before any Owner is known.
 *
 * Combined with a per-Owner `clientEntityId` — available only after the
 * Social Session response — to form the full {@link OwnerKeyIdentity} the
 * secure-key store resolves. Kept as its own type so the two are
 * never silently conflated: an app-level identity cannot select an AuthKey by
 * itself, and code that only has one cannot pretend otherwise.
 */
export type AppKeyIdentity = Readonly<{
  appId: string
  environment: DaaEnvironment
}>

/**
 * Identity that namespaces the installation AuthKey: one non-exportable
 * P-256/ES256 key per `{appId, environment, clientEntityId (Owner),
 * installation}`.
 *
 * `clientEntityId` must be the SERVER-CONFIRMED value the Social Session
 * response echoed back — never a caller-supplied value the SDK has not
 * validated. See `models/PreparedSocialLogin.ts#completeSocialSession`.
 *
 * The raw value never reaches native or the alias in the clear: `alias.ts`
 * only ever folds it into `deriveKeyScope`'s SHA-256 digest.
 */
export type OwnerKeyIdentity = AppKeyIdentity &
  Readonly<{
    clientEntityId: string
  }>

/**
 * Result of resolving the installation AuthKey. Same name and same two cases as
 * the native SDKs' `AuthKeyResolution` (`daa-ios-sdk`, `daa-android-sdk`), so
 * the discriminant is not renamed or re-interpreted as it crosses the bridge.
 *
 * This is about REGISTRATION state, not about which call minted the key:
 *
 * - `created` — the key was just minted, OR a key already exists but carries no
 *   durable registration acknowledgement. Per the native SDK contract, passcode
 *   removal, Keychain reset, device restore, or a crash before acknowledgement
 *   all resolve to `created` rather than silently presenting an unregistered
 *   key as registered.
 * - `existing` — returned only for a key with a durable acknowledgement, i.e.
 *   after {@link OwnerAuthKey.acknowledgeRegistration} has succeeded.
 */
export type AuthKeyResolution = 'created' | 'existing'

/**
 * The DAA Owner AuthKey.
 *
 * The private key never leaves the secure key handle. There is deliberately NO
 * generic `sign(bytes)` at the SDK surface — signing is reachable only through
 * this DAA-specific API, for defined DAA operations (login completion, protected
 * writes, signed context refresh). See SECURITY.md.
 *
 * **Not the ephemeral registration-flow key.** The login contract has two
 * P-256 keys, and this is the durable, namespaced, enclave-held one. The other —
 * per login attempt, anonymous, process memory only, exported at Prepare — is
 * `auth/RegistrationFlowKey.ts`, which never comes from this store and carries a
 * comparison table for the difference.
 */
export interface OwnerAuthKey {
  /** Unpadded Base64URL DER SubjectPublicKeyInfo of the public key. */
  publicKeySpkiBase64Url(): Promise<string>

  /** RFC 7638 JWK thumbprint (`jkt`) of the P-256 public key. */
  thumbprint(): Promise<string>

  /**
   * Registration state of this handle: `created` while Circle's acknowledgement
   * is still outstanding, `existing` once it is durably recorded. Read from the
   * value the store observed when it resolved the key, and refreshed locally by
   * {@link acknowledgeRegistration}.
   */
  resolution(): AuthKeyResolution

  /**
   * Persist that Circle registered this public key, moving the handle from
   * `created` to `existing`. Idempotent: a no-op once the handle is `existing`.
   *
   * Per the native SDK contract the caller invokes this only AFTER Circle has
   * successfully registered the exported SPKI. Device Registration Complete
   * calls it on an `ACTIVE` result. `RECOVERY_PENDING` must not.
   */
  acknowledgeRegistration(): Promise<void>

  /**
   * Produce an ES256 signature (JOSE `R || S`, 64 bytes) over the exact message
   * bytes. The caller passes the already-serialized signing input; this method
   * does not reserialize or canonicalize.
   *
   * This seam does NOT gate on {@link resolution}. Registered-device
   * authorization (`auth/deviceAuthorization.ts`) requires `existing` before it
   * calls this. Production `NativeSecureKeyStore` reaches native
   * `signDeviceAuthorization`, which rejects with `authKeyRegistrationRequired`
   * until acknowledgement succeeds (except native-allowed login completion).
   * There is no public generic `sign(bytes)`.
   *
   * **Post-activation only.** Do not call this for the Device Registration
   * Complete device proof — see {@link signRegistrationDeviceAuthorization}.
   */
  signExactBytes(message: Uint8Array): Promise<Uint8Array>

  /**
   * Produce an ES256 signature (JOSE `R || S`, 64 bytes) over the exact
   * Device Registration Complete device-proof signing input
   * (`auth/registrationAuthorization.ts`'s `X-Device-Authorization`, the
   * registration profile's claim/header shape, not the post-activation one
   * of the same header name).
   *
   * A DIFFERENT native seam from {@link signExactBytes}, on purpose: this key
   * has typically not been acknowledged yet (Complete runs before
   * `acknowledgeRegistration`), and the registration profile's claim set and
   * embedded-JWK header are validated by native's registration validator, not
   * `DaaDeviceAuthorizationSigningInput`. Production `NativeSecureKeyStore`
   * reaches native `signRegistrationDeviceAuthorization`. Routing this proof
   * through `signExactBytes` instead would sign valid bytes against the wrong
   * native validator and fail on a real device even though it looks correct
   * in this SDK's own JWS construction.
   */
  signRegistrationDeviceAuthorization(message: Uint8Array): Promise<Uint8Array>
}

export interface SecureKeyStore {
  /** Resolve the installation AuthKey, creating it only when absent. */
  resolveOrCreate(identity: OwnerKeyIdentity): Promise<OwnerAuthKey>
}
