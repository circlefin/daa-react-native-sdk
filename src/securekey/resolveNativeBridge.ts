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

import { requireOptionalNativeModule } from 'expo-modules-core'
import { DEVICE_KEY_POLICY, isRecord } from '../config'
import type { DeviceKeyPolicy } from '../config'
import { contractViolation } from '../errors'
import { parseSecureKeyAlias } from './alias'
import type { NativeAuthKeyResolution, NativeSecureKeyBridge } from './NativeSecureKeyBridge'

// JS shape of the Expo `DaaSecureKey` native module. Identity is passed as
// structured `{appId, environment}` fields after TypeScript parses the RN
// alias; the native module owns the per-install UUID and constructs
// `DaaAuthKeyIdentity`.
interface DaaSecureKeyNativeModule {
  /**
   * The DeviceKeyPolicy this native module was built to enforce. This is a
   * version-skew guard, not a live capability readback: it is a compiled-in
   * constant on both sides of the bridge (mirrors `DEVICE_KEY_POLICY`), so a
   * mismatch means the JS and native module versions disagree about the
   * closed set, not that a specific key's real hardware/OS protection was
   * measured and found wanting. Neither native SDK exposes a public API for
   * that.
   */
  declaredKeyPolicy?: () => unknown
  resolveOrCreate(appId: string, environment: string): Promise<string>
  publicKeySpkiBase64Url(appId: string, environment: string): Promise<string>
  acknowledgeRegistration(appId: string, environment: string): Promise<void>
  signDeviceAuthorization(
    appId: string,
    environment: string,
    signingInputBase64Url: string,
  ): Promise<string>
  /**
   * The registration-profile counterpart of {@link signDeviceAuthorization}.
   * A separate native function with a separate validator
   * (`DaaRegistrationAuthorizationSigningInput`), not an overload — see
   * `NativeSecureKeyBridge.signRegistrationDeviceAuthorization`.
   */
  signRegistrationDeviceAuthorization(
    appId: string,
    environment: string,
    signingInputBase64Url: string,
  ): Promise<string>
}

/**
 * When the Expo `DaaSecureKey` module is loaded, require that its declared
 * policy matches the configured closed set. No-ops when the module is absent
 * (Node / Jest) so Prepare can still construct a client.
 *
 * This is a version-skew guard between the JS and native module, not a live
 * attestation of a specific key's real protection level — see
 * `declaredKeyPolicy` on `DaaSecureKeyNativeModule` above.
 */
export function assertNativeModuleKeyPolicyIfPresent(configured: DeviceKeyPolicy): void {
  const native = requireOptionalNativeModule<DaaSecureKeyNativeModule>('DaaSecureKey')
  if (native === null) {
    return
  }
  assertNativeDeclaredKeyPolicy(native, configured)
}

function assertNativeDeclaredKeyPolicy(
  native: DaaSecureKeyNativeModule,
  configured: DeviceKeyPolicy,
): void {
  const query = native.declaredKeyPolicy
  if (typeof query !== 'function') {
    throw contractViolation('native DaaSecureKey module did not declare a DeviceKeyPolicy')
  }
  const declared = query.call(native)
  if (
    !isRecord(declared) ||
    declared['hardwareBacked'] !== configured.hardwareBacked ||
    declared['userVerification'] !== configured.userVerification
  ) {
    throw contractViolation(
      'native DaaSecureKey declared keyPolicy does not match the configured DeviceKeyPolicy',
    )
  }
}

// Production wiring to the platform native module (Swift under ios/, Kotlin
// under android/), resolved via expo-modules-core.
//
// Node / Jest have no native module: fail closed rather than silently no-op.
// Tests inject a NativeSecureKeyBridge explicitly.
export function resolveNativeBridge(): NativeSecureKeyBridge {
  const native = requireOptionalNativeModule<DaaSecureKeyNativeModule>('DaaSecureKey')
  if (native === null) {
    throw contractViolation(
      'native DaaSecureKey module is not available. Provide a NativeSecureKeyBridge ' +
        'explicitly, or run inside a React Native app that includes the DaaSecureKey Expo ' +
        'module.',
    )
  }
  assertNativeDeclaredKeyPolicy(native, DEVICE_KEY_POLICY)
  return wrapNativeModule(native)
}

function wrapNativeModule(native: DaaSecureKeyNativeModule): NativeSecureKeyBridge {
  return {
    async resolveOrCreate(alias: string): Promise<NativeAuthKeyResolution> {
      const identity = parseSecureKeyAlias(alias)
      const resolution = await native.resolveOrCreate(identity.appId, identity.environment)
      if (resolution === 'created' || resolution === 'existing') {
        return resolution
      }
      throw contractViolation('native resolveOrCreate returned an unknown resolution')
    },

    async publicKeySpkiBase64Url(alias: string): Promise<string> {
      const identity = parseSecureKeyAlias(alias)
      return await native.publicKeySpkiBase64Url(identity.appId, identity.environment)
    },

    async acknowledgeRegistration(alias: string): Promise<void> {
      // Calls the acknowledgeRegistration the Expo module already exposes on
      // both platforms; no parallel native API is introduced. Native owns
      // idempotence and persistence (Data Protection Keychain on iOS,
      // app-private storage on Android).
      const identity = parseSecureKeyAlias(alias)
      await native.acknowledgeRegistration(identity.appId, identity.environment)
    },

    async sign(alias: string, messageBase64Url: string): Promise<string> {
      // Typed native signDeviceAuthorization — not a generic sign(bytes) Expo
      // method. `messageBase64Url` is the exact compact-JWS signing input
      // `deviceAuthorization.ts` already constructed. Native wraps those bytes
      // in DaaDeviceAuthorizationSigningInput (validates, does not re-encode)
      // and returns 64-byte JOSE R||S as unpadded Base64URL.
      if (typeof native.signDeviceAuthorization !== 'function') {
        throw contractViolation('native DaaSecureKey.signDeviceAuthorization is required')
      }
      const identity = parseSecureKeyAlias(alias)
      return await native.signDeviceAuthorization(
        identity.appId,
        identity.environment,
        messageBase64Url,
      )
    },

    async signRegistrationDeviceAuthorization(
      alias: string,
      messageBase64Url: string,
    ): Promise<string> {
      // Typed native signRegistrationDeviceAuthorization — the registration
      // counterpart of `sign` above, NOT the same native call. `messageBase64Url`
      // is the exact compact-JWS signing input `registrationAuthorization.ts`
      // already constructed. Native wraps those bytes in
      // DaaRegistrationAuthorizationSigningInput (a different validator from
      // DaaDeviceAuthorizationSigningInput: registration `typ`s, an embedded
      // JWK header, and the 14-claim registration payload) and returns the
      // 64-byte JOSE R||S signature as unpadded Base64URL. Unlike `sign`, this
      // does not require a durably acknowledged key.
      if (typeof native.signRegistrationDeviceAuthorization !== 'function') {
        throw contractViolation(
          'native DaaSecureKey.signRegistrationDeviceAuthorization is required',
        )
      }
      const identity = parseSecureKeyAlias(alias)
      return await native.signRegistrationDeviceAuthorization(
        identity.appId,
        identity.environment,
        messageBase64Url,
      )
    },
  }
}
