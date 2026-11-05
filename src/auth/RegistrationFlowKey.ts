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

// The ephemeral registration-flow key.
//
// ============================================================================
// THIS IS NOT AN AuthKey. Do not treat it as one, and do not route it through
// `SecureKeyStore`.
// ============================================================================
//
// The login contract uses two different P-256 keys, and confusing
// them is the failure this file's naming exists to prevent:
//
// | | AuthKey (`OwnerAuthKey`, `securekey/`) | registration-flow key (this file) |
// | --- | --- | --- |
// | Lifetime | durable, survives the app | **one login attempt** |
// | Scope | `{environment, customer application, Owner (clientEntityId), installation}` | nothing; it is anonymous |
// | Storage | Secure Enclave / Android Keystore, via `SecureKeyStore` | process memory only |
// | Exported at | Device Registration Complete (`authKeyPublicKey`) | **Prepare** (`registrationFlowPublicKey`) |
// | Selected | only *after* the Social Session response | before Prepare |
// | Authorizes | DAA operations, via `X-Device-Authorization` | nothing |
//
// The contract says the same thing in one line on
// `PrepareSocialLoginRequest.registrationFlowPublicKey`: "Unpadded Base64URL DER
// SubjectPublicKeyInfo for an ephemeral P-256 flow key; **it is not an AuthKey**".
//
// Its whole job is to prove, at Device Registration Complete, that the caller
// completing the registration is the caller that prepared it — the flow-key JWS
// is one of the two fresh proofs over the exact Complete request bytes. Because
// it is per-attempt and anonymous, it deliberately does NOT go into the
// enclave: a key in the Secure Enclave is a key that outlives the attempt and
// acquires a namespace, which is exactly what this one must not have.
//
// Signing is a **typed Complete-only helper**, not a public `sign(bytes)`. The
// member is `signExactBytes` of the JWS signing input for
// `X-Registration-Flow-Authorization`. It is not exported from `index.ts`.
// Both the native Expo bridge (`DaaRegistrationFlowKey.signRegistrationAuthorization`
// on iOS and Android) and the WebCrypto test stand-in sign for real, so Device
// Registration Complete can finish on a physical device.

import { fromBase64Url, toBase64Url } from '../crypto/base64url'
import { toArrayBuffer } from '../crypto/bytes'
import { contractViolation } from '../errors'
import {
  nativeGenerateRegistrationFlowKey,
  nativeRegistrationFlowPublicKeySpkiBase64Url,
  nativeReleaseRegistrationFlowKey,
  nativeSignRegistrationAuthorization,
  requireDaaRegistrationNative,
  type DaaRegistrationNativeModule,
} from './daaRegistrationNative'

/** Byte length of a P-256 SubjectPublicKeyInfo. */
const P256_SPKI_BYTE_LENGTH = 91

/**
 * One attempt's registration-flow key. Not an AuthKey; see the file header.
 *
 * The interface carries the public-key export for Prepare, the Complete-only
 * signing helper, and an explicit release: the native implementations hold the
 * private key in a process-lifetime cache, so something has to say when it is
 * no longer needed.
 */
export interface RegistrationFlowKey {
  /**
   * Unpadded Base64URL DER SubjectPublicKeyInfo of the public key, the exact
   * form `PrepareSocialLoginRequest.registrationFlowPublicKey` wants.
   */
  publicKeySpkiBase64Url(): Promise<string>

  /**
   * ES256 signature (JOSE `R || S`, 64 bytes) over the exact Device Registration
   * Complete flow-JWS signing input. Not a public generic sign API.
   */
  signExactBytes(message: Uint8Array): Promise<Uint8Array>

  /**
   * Discard the key, so a native implementation stops holding its private half.
   *
   * Safe to call more than once and safe to call on a key that was never used.
   * The key is dead afterwards: `publicKeySpkiBase64Url()` on a released native
   * key fails closed rather than returning a stale value.
   *
   * Device Registration Complete is the owner of this call: it signs, then
   * releases. `PreparedSocialLogin.abandon()` is the other caller when the user
   * backs out of provider login. `PendingDeviceRegistration` has no
   * `abandon()`: after Session, the key is held until Complete or until the
   * process exits.
   */
  release(): Promise<void>
}

/**
 * Source of per-attempt registration-flow keys.
 *
 * A seam so `AuthClient` can switch providers without changing callers.
 * Production generation is `DaaRegistrationFlowKey` in `daa-ios-sdk` /
 * `daa-android-sdk` — not `DaaSecureKey`, which is the Owner AuthKey. The Expo
 * `DaaRegistration` module bridges that type and keeps the private key in
 * native memory. WebCrypto is an explicit test stand-in
 * (`webCryptoRegistrationFlowKeyProvider`), never a fallback. A host missing
 * the Expo module fails closed. The seam is not exported from `index.ts`: a
 * consumer cannot substitute the key that proves its own registration handoff.
 */
export interface RegistrationFlowKeyProvider {
  generate(): Promise<RegistrationFlowKey>
}

class WebCryptoRegistrationFlowKey implements RegistrationFlowKey {
  readonly #keyPair: CryptoKeyPair

  constructor(keyPair: CryptoKeyPair) {
    this.#keyPair = keyPair
    Object.freeze(this)
  }

  // Nothing to free: the CryptoKey is ordinary garbage once the handle is
  // dropped, and WebCrypto exposes no destroy. Present so the two providers
  // satisfy one interface.
  async release(): Promise<void> {}

  async publicKeySpkiBase64Url(): Promise<string> {
    const spki = await subtle().exportKey('spki', this.#keyPair.publicKey)
    const bytes = new Uint8Array(spki)
    if (bytes.length !== P256_SPKI_BYTE_LENGTH) {
      throw contractViolation(
        'registration-flow key did not export a 91-byte P-256 SubjectPublicKeyInfo',
      )
    }
    return toBase64Url(bytes)
  }

  async signExactBytes(message: Uint8Array): Promise<Uint8Array> {
    const signature = await subtle().sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      this.#keyPair.privateKey,
      toArrayBuffer(message),
    )
    return new Uint8Array(signature)
  }
}

class NativeRegistrationFlowKey implements RegistrationFlowKey {
  readonly #native: DaaRegistrationNativeModule
  readonly #id: string

  constructor(native: DaaRegistrationNativeModule, id: string) {
    this.#native = native
    this.#id = id
    Object.freeze(this)
  }

  async publicKeySpkiBase64Url(): Promise<string> {
    const spki = nativeRegistrationFlowPublicKeySpkiBase64Url(this.#native, this.#id)
    const bytes = decodeSpki(spki)
    return toBase64Url(bytes)
  }

  async release(): Promise<void> {
    nativeReleaseRegistrationFlowKey(this.#native, this.#id)
  }

  async signExactBytes(message: Uint8Array): Promise<Uint8Array> {
    // The Expo module holds the private key; only the exact bytes and the
    // resulting signature cross the bridge as Base64URL strings.
    const signingInputBase64Url = toBase64Url(message)
    return nativeSignRegistrationAuthorization(this.#native, this.#id, signingInputBase64Url)
  }
}

/**
 * Production React Native provider: native `DaaRegistrationFlowKey` via the
 * Expo `DaaRegistration` module. The private key never crosses the bridge.
 */
export function nativeRegistrationFlowKeyProvider(
  native: DaaRegistrationNativeModule,
): RegistrationFlowKeyProvider {
  return {
    async generate(): Promise<RegistrationFlowKey> {
      const id = nativeGenerateRegistrationFlowKey(native)
      return new NativeRegistrationFlowKey(native, id)
    },
  }
}

/**
 * Node/Jest stand-in: a non-extractable WebCrypto P-256 keypair per attempt.
 *
 * `extractable: false` is set even though the key never leaves the process. It
 * costs nothing, and it means a future bug that hands the handle somewhere else
 * still cannot export the private key.
 *
 * **Not the production RN path.** Production `defaultRegistrationFlowKeyProvider`
 * never calls this. Absent `crypto.subtle`, `generate()` fails closed with
 * `contract_violation` rather than weaker key generation.
 */
export function webCryptoRegistrationFlowKeyProvider(): RegistrationFlowKeyProvider {
  return {
    async generate(): Promise<RegistrationFlowKey> {
      const keyPair = (await subtle().generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
        'sign',
        'verify',
      ])) as CryptoKeyPair
      return new WebCryptoRegistrationFlowKey(keyPair)
    },
  }
}

/**
 * Native `DaaRegistrationFlowKey` via the Expo module. A missing module is a
 * `contract_violation` — WebCrypto is never a fallback. The native module is
 * resolved on `generate()`, not when this provider is constructed, so building
 * a `DaaClient` does not require the Expo module to be linked.
 */
export function defaultRegistrationFlowKeyProvider(): RegistrationFlowKeyProvider {
  return {
    async generate(): Promise<RegistrationFlowKey> {
      return nativeRegistrationFlowKeyProvider(requireDaaRegistrationNative()).generate()
    },
  }
}

/** Drop the key without replacing the failure that triggered cleanup. */
export async function releaseQuietly(key: RegistrationFlowKey): Promise<void> {
  try {
    await key.release()
  } catch {
    // Intentionally empty: a throwing release must not mask the originating error.
  }
}

function decodeSpki(spki: string): Uint8Array {
  let bytes: Uint8Array
  try {
    bytes = fromBase64Url(spki)
  } catch {
    throw contractViolation(
      'registration-flow key did not export valid Base64URL SubjectPublicKeyInfo',
    )
  }
  if (bytes.length !== P256_SPKI_BYTE_LENGTH) {
    throw contractViolation(
      'registration-flow key did not export a 91-byte P-256 SubjectPublicKeyInfo',
    )
  }
  return bytes
}

function subtle(): SubtleCrypto {
  const host = (globalThis as { crypto?: Crypto }).crypto
  if (host === undefined || host.subtle === undefined) {
    throw contractViolation(
      'crypto.subtle is required to generate the ephemeral registration-flow key; ' +
        'install a WebCrypto polyfill in the host app or supply a native ' +
        'DaaRegistrationFlowKey provider',
    )
  }
  return host.subtle
}
