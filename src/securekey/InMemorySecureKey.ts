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

import { toBase64Url } from '../crypto/base64url'
import { toArrayBuffer } from '../crypto/bytes'
import { p256JwkThumbprint } from '../crypto/jwkThumbprint'
import { secureKeyAlias } from './alias'
import type { AuthKeyResolution, OwnerAuthKey, OwnerKeyIdentity, SecureKeyStore } from './SecureKey'

// A WebCrypto-backed, in-memory implementation of the DAA Owner-key API. It
// produces real P-256/ES256 signatures so it can drive golden vectors and unit
// tests WITHOUT native hardware. It is NOT a production secure-key
// implementation: keys live in process memory, not a secure enclave/keystore.

function getSubtle(): SubtleCrypto {
  const c = (globalThis as { crypto?: Crypto }).crypto
  if (!c || !c.subtle) {
    throw new Error('DAA: WebCrypto (crypto.subtle) is not available')
  }
  return c.subtle
}

function assertDevelopmentEnvironment(): void {
  const g = globalThis as { __DEV__?: boolean; process?: { env?: { NODE_ENV?: string } } }
  const nodeEnvironment = g.process?.env?.NODE_ENV
  const explicitlyProduction = g.__DEV__ === false || nodeEnvironment === 'production'
  const explicitlyDevelopment =
    g.__DEV__ === true || nodeEnvironment === 'development' || nodeEnvironment === 'test'
  if (explicitlyProduction) {
    throw new Error(
      'DAA: InMemorySecureKeyStore is a test double and must not be used in ' +
        'production; wire the native secure-key store instead.',
    )
  }
  if (!explicitlyDevelopment) {
    throw new Error(
      'DAA: InMemorySecureKeyStore requires an explicit development or test ' +
        'environment marker (__DEV__ or NODE_ENV).',
    )
  }
}

class InMemoryOwnerAuthKey implements OwnerAuthKey {
  // There is no durable store behind this double, so a handle always starts
  // unacknowledged and the state lives only as long as the handle does. The
  // native store persists the equivalent state in the OS keystore.
  #acknowledged = false
  readonly #keyPair: CryptoKeyPair

  constructor(keyPair: CryptoKeyPair) {
    this.#keyPair = keyPair
  }

  resolution(): AuthKeyResolution {
    return this.#acknowledged ? 'existing' : 'created'
  }

  async acknowledgeRegistration(): Promise<void> {
    this.#acknowledged = true
  }

  async publicKeySpkiBase64Url(): Promise<string> {
    const spki = await getSubtle().exportKey('spki', this.#keyPair.publicKey)
    return toBase64Url(new Uint8Array(spki))
  }

  async thumbprint(): Promise<string> {
    // Same one-place RFC 7638 derivation the native store uses.
    const spki = await getSubtle().exportKey('spki', this.#keyPair.publicKey)
    return p256JwkThumbprint(new Uint8Array(spki))
  }

  async signExactBytes(message: Uint8Array): Promise<Uint8Array> {
    const sig = await getSubtle().sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      this.#keyPair.privateKey,
      toArrayBuffer(message),
    )
    return new Uint8Array(sig) // JOSE R || S, 64 bytes.
  }

  async signRegistrationDeviceAuthorization(message: Uint8Array): Promise<Uint8Array> {
    // This test double has no separate native validators to route between —
    // it is one WebCrypto key signing whatever exact bytes it is given
    // either way. The two methods exist here only so this class satisfies
    // OwnerAuthKey and a test can assert on WHICH method the production
    // caller reached; native's two validators are what actually diverge.
    return this.signExactBytes(message)
  }
}

export class InMemorySecureKeyStore implements SecureKeyStore {
  readonly #keys = new Map<string, Promise<OwnerAuthKey>>()

  constructor() {
    assertDevelopmentEnvironment()
  }

  async resolveOrCreate(identity: OwnerKeyIdentity): Promise<OwnerAuthKey> {
    const id = secureKeyAlias(identity)
    let existing = this.#keys.get(id)
    if (!existing) {
      // Evict on failure so a transient error (e.g. crypto.subtle not yet
      // available) is not memoized permanently for this identity.
      existing = this.#generate().catch((err: unknown) => {
        this.#keys.delete(id)
        throw err
      })
      this.#keys.set(id, existing)
    }
    return existing
  }

  async #generate(): Promise<OwnerAuthKey> {
    const keyPair = (await getSubtle().generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      // Non-exportable private key; the public key is still exportable.
      false,
      ['sign', 'verify'],
    )) as CryptoKeyPair
    return new InMemoryOwnerAuthKey(keyPair)
  }
}
