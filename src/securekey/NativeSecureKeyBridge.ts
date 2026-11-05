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

// The JS <-> native contract implemented by the platform secure-key module
// (iOS Keychain / Secure Enclave, Android Keystore).
//
// Keys are non-exportable and referenced by an opaque `alias`. Private key bytes
// never cross this boundary. All byte-valued arguments and results are unpadded
// Base64URL strings so the contract is uniform across the RN bridge.
//
// The Expo `DaaSecureKey` module under ios/ and android/ implements this
// contract by delegating to daa-ios-sdk / daa-android-sdk. Production apps
// resolve it via resolveNativeBridge(); tests inject a stand-in.
//
// Every method here takes the RN `alias`; resolveNativeBridge() parses it into
// the structured `{appId, environment}` pair the Expo module accepts.
import type { AuthKeyResolution } from './SecureKey'

// The bridge-side name for the public `AuthKeyResolution`.
export type NativeAuthKeyResolution = AuthKeyResolution

export interface NativeSecureKeyBridge {
  /**
   * Ensure a non-exportable P-256 key exists for `alias`, creating it only when
   * absent. Idempotent.
   *
   * Returns the native SDKs' resolution discriminant, which is about
   * REGISTRATION state, not merely whether this call minted the key:
   * `'created'` when the key was just minted OR when an existing key carries no
   * durable registration acknowledgement; `'existing'` only for a key Circle is
   * durably recorded as having registered. `acknowledgeRegistration` is what
   * moves a key from the former to the latter.
   */
  resolveOrCreate(alias: string): Promise<NativeAuthKeyResolution>

  /** Unpadded Base64URL DER SubjectPublicKeyInfo of the public key. */
  publicKeySpkiBase64Url(alias: string): Promise<string>

  /**
   * Persist that Circle registered the public key for `alias`. Idempotent —
   * native no-ops when the key is already acknowledged. After it succeeds,
   * later `resolveOrCreate` calls return `'existing'`.
   */
  acknowledgeRegistration(alias: string): Promise<void>

  // The RFC 7638 thumbprint is derived in TypeScript from the SPKI above (see
  // crypto/jwkThumbprint), so the native module does not implement it — one
  // canonicalization, no cross-platform drift. Native thumbprint() is not
  // called at this seam.

  /**
   * ES256 signature over the exact message bytes.
   *
   * Production `resolveNativeBridge()` sends those bytes to Expo
   * `signDeviceAuthorization` (native `DaaSecureKey.signDeviceAuthorization`
   * + `DaaDeviceAuthorizationSigningInput`). There is no native generic
   * `sign(bytes)` Expo method. Compact JWS construction lives in
   * `auth/deviceAuthorization.ts` and signs through `OwnerAuthKey.signExactBytes`.
   * Native validates the compact signing input and signs that same slice.
   * The header carries the published `typ` as-is.
   *
   * Injectable test stand-ins may still implement this for NativeSecureKeyStore
   * unit tests (including arbitrary bytes the native validator would reject).
   *
   * @param messageBase64Url unpadded Base64URL of the exact bytes to sign.
   * @returns unpadded Base64URL of the 64-byte JOSE `R || S` signature.
   */
  sign(alias: string, messageBase64Url: string): Promise<string>

  /**
   * ES256 signature over the exact Device Registration Complete device-proof
   * signing input.
   *
   * A DISTINCT method from {@link sign}, not an overload or a shared code
   * path: production `resolveNativeBridge()` sends these bytes to Expo
   * `signRegistrationDeviceAuthorization` (native
   * `DaaSecureKey.signRegistrationDeviceAuthorization` +
   * `DaaRegistrationAuthorizationSigningInput`), which is a different native
   * function with a different validator than `signDeviceAuthorization` +
   * `DaaDeviceAuthorizationSigningInput` behind {@link sign}. The registration
   * profile is built in `auth/registrationAuthorization.ts` and signs through
   * `OwnerAuthKey.signRegistrationDeviceAuthorization`. Native validates the
   * compact signing input and signs that same slice; it does not require a
   * durably acknowledged key, because Complete runs before
   * `acknowledgeRegistration`.
   *
   * Injectable test stand-ins may still implement this for NativeSecureKeyStore
   * unit tests (including arbitrary bytes the native validator would reject).
   *
   * @param messageBase64Url unpadded Base64URL of the exact bytes to sign.
   * @returns unpadded Base64URL of the 64-byte JOSE `R || S` signature.
   */
  signRegistrationDeviceAuthorization(alias: string, messageBase64Url: string): Promise<string>
}
