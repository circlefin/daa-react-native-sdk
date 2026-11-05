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

import { fromBase64Url, toBase64Url } from '../crypto/base64url'
import { p256JwkThumbprint } from '../crypto/jwkThumbprint'
import { contractViolation, mapNativeError } from '../errors'
import { secureKeyAlias } from './alias'
import type { NativeSecureKeyBridge } from './NativeSecureKeyBridge'
import type { AuthKeyResolution, OwnerAuthKey, OwnerKeyIdentity, SecureKeyStore } from './SecureKey'

// Production DAA Owner-key store backed by the platform secure-key module. It
// holds no key material itself — every operation delegates to the native bridge,
// which keeps the non-exportable private key behind the OS keystore/enclave.
//
// The bridge is injected so this class is unit-testable without native hardware
// (see src/__test__/nativeSecureKey.test.ts). Production wiring resolves the
// real native module via resolveNativeBridge().
//
// The `'created' | 'existing'` discriminant native returns from resolveOrCreate
// is retained on the handle rather than discarded, so a caller can tell an
// AuthKey still awaiting Circle's registration acknowledgement from one that
// already has it. It is deliberately NOT flattened at this seam.

// The alias namespaces one key per `{appId, environment, clientEntityId}` —
// per Owner, not per installation (see secureKeyAlias).
// The Expo module parses that alias in TypeScript, then constructs native
// `DaaAuthKeyIdentity` with a durable per-install UUID it owns (app-container
// file excluded from backup on iOS, app-private no-backup storage on Android;
// both are deleted on uninstall). Native key tags therefore include the
// installation UUID.

// Run a native bridge call, mapping any rejection onto DaaSdkError so raw
// keystore/enclave text never reaches the caller.
async function guardNative<T>(op: () => Promise<T>): Promise<T> {
  try {
    return await op()
  } catch (err) {
    throw mapNativeError(err)
  }
}

// Decode a Base64URL value the native module returned and assert its exact byte
// length — the seam is the last place to enforce the OwnerAuthKey contract
// before these values reach the wire or pin an Owner key.
function decodeExact(value: string, expected: number, what: string): Uint8Array {
  let bytes: Uint8Array
  try {
    bytes = fromBase64Url(value)
  } catch {
    throw contractViolation(`native ${what} is not valid Base64URL`)
  }
  if (bytes.length !== expected) {
    throw contractViolation(`native ${what} must be ${expected} bytes; got ${bytes.length}`)
  }
  return bytes
}

// Re-validate the discriminant at the store seam. resolveNativeBridge() already
// checks it for the production module, but an injected stand-in is untyped at
// runtime, so a third value must fail closed here too rather than being pinned
// onto a handle and read back later as if it were meaningful.
function parseNativeResolution(value: unknown): AuthKeyResolution {
  if (value === 'created' || value === 'existing') {
    return value
  }
  throw contractViolation('native resolveOrCreate must return created or existing')
}

class NativeOwnerAuthKey implements OwnerAuthKey {
  #resolution: AuthKeyResolution
  #acknowledging: Promise<void> | null = null
  readonly #bridge: NativeSecureKeyBridge
  readonly #alias: string

  constructor(bridge: NativeSecureKeyBridge, alias: string, resolution: AuthKeyResolution) {
    this.#bridge = bridge
    this.#alias = alias
    this.#resolution = resolution
  }

  resolution(): AuthKeyResolution {
    return this.#resolution
  }

  async acknowledgeRegistration(): Promise<void> {
    if (this.#resolution === 'existing') {
      return
    }
    if (this.#acknowledging === null) {
      // De-duplicate concurrent callers on one handle to a single native round
      // trip, the same way NativeSecureKeyStore.resolveOrCreate does. The
      // `existing` check above cannot do it alone: it is synchronous, so two
      // callers that do not await between them both observe `created`.
      //
      // Cleared on failure so a transient native error stays retryable and is
      // not memoized as a permanently poisoned acknowledgement.
      this.#acknowledging = guardNative(() => this.#bridge.acknowledgeRegistration(this.#alias))
        .then(() => {
          this.#resolution = 'existing'
        })
        .catch((err: unknown) => {
          this.#acknowledging = null
          throw err
        })
    }
    return this.#acknowledging
  }

  async publicKeySpkiBase64Url(): Promise<string> {
    const spki = await guardNative(() => this.#bridge.publicKeySpkiBase64Url(this.#alias))
    decodeExact(spki, 91, 'public key (P-256 SPKI)') // P-256 SPKI is exactly 91 DER bytes
    return spki
  }

  async thumbprint(): Promise<string> {
    // Derived in TS from the (length-checked) SPKI — one RFC 7638 implementation
    // shared with the in-memory store; no native thumbprint to drift.
    const spki = await this.publicKeySpkiBase64Url()
    return p256JwkThumbprint(fromBase64Url(spki))
  }

  async signExactBytes(message: Uint8Array): Promise<Uint8Array> {
    const raw = await guardNative(() => this.#bridge.sign(this.#alias, toBase64Url(message)))
    // A native module that forgets DER -> R||S returns ~70 bytes that decode
    // cleanly; the exact-length check catches it here, before the wire.
    return decodeExact(raw, 64, 'signature (JOSE R||S; convert DER ECDSA to R||S)')
  }

  async signRegistrationDeviceAuthorization(message: Uint8Array): Promise<Uint8Array> {
    // A DIFFERENT bridge call from signExactBytes/sign above — see
    // SecureKey.ts and NativeSecureKeyBridge.ts for why the registration
    // device proof cannot share the post-activation seam.
    const raw = await guardNative(() =>
      this.#bridge.signRegistrationDeviceAuthorization(this.#alias, toBase64Url(message)),
    )
    return decodeExact(raw, 64, 'registration signature (JOSE R||S; convert DER ECDSA to R||S)')
  }
}

export class NativeSecureKeyStore implements SecureKeyStore {
  readonly #keys = new Map<string, Promise<OwnerAuthKey>>()
  readonly #bridge: NativeSecureKeyBridge

  constructor(bridge: NativeSecureKeyBridge) {
    this.#bridge = bridge
  }

  async resolveOrCreate(identity: OwnerKeyIdentity): Promise<OwnerAuthKey> {
    const alias = secureKeyAlias(identity)
    let existing = this.#keys.get(alias)
    if (!existing) {
      // Evict on failure so a transient native error is not memoized forever;
      // map the native rejection onto DaaSdkError.
      existing = guardNative(() => this.#bridge.resolveOrCreate(alias))
        .then((raw) => new NativeOwnerAuthKey(this.#bridge, alias, parseNativeResolution(raw)))
        .catch((err: unknown) => {
          this.#keys.delete(alias)
          throw err
        })
      this.#keys.set(alias, existing)
    }
    return existing
  }
}
