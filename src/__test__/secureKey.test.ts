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

import { fromBase64Url } from '../crypto/base64url'
import { toArrayBuffer } from '../crypto/bytes'
import { InMemorySecureKeyStore } from '../testing'

const CLIENT_ENTITY_ID = '00000000-0000-4000-8000-000000000001'

const identity = {
  appId: 'app-123',
  environment: 'sandbox',
  clientEntityId: CLIENT_ENTITY_ID,
} as const

describe('InMemorySecureKeyStore', () => {
  it('returns the same installation key for the same identity', async () => {
    const store = new InMemorySecureKeyStore()
    const a = await store.resolveOrCreate(identity)
    const b = await store.resolveOrCreate(identity)
    expect(a).toBe(b)
  })

  it('reports created until acknowledgement, then existing', async () => {
    const key = await new InMemorySecureKeyStore().resolveOrCreate(identity)
    expect(key.resolution()).toBe('created')
    await key.acknowledgeRegistration()
    expect(key.resolution()).toBe('existing')
  })

  it('exposes a non-empty SPKI public key and a stable thumbprint', async () => {
    const key = await new InMemorySecureKeyStore().resolveOrCreate(identity)
    const spki = await key.publicKeySpkiBase64Url()
    expect(spki.length).toBeGreaterThan(0)

    const t1 = await key.thumbprint()
    const t2 = await key.thumbprint()
    expect(t1).toBe(t2)
    expect(t1.length).toBeGreaterThan(0)
  })

  it('signs exact bytes as a 64-byte ES256 (R||S) signature that verifies', async () => {
    const key = await new InMemorySecureKeyStore().resolveOrCreate(identity)
    const message = new TextEncoder().encode('{"idempotencyKey":"k"}')
    const sig = await key.signExactBytes(message)
    expect(sig.length).toBe(64)

    const spki = fromBase64Url(await key.publicKeySpkiBase64Url())
    const verifyKey = await globalThis.crypto.subtle.importKey(
      'spki',
      toArrayBuffer(spki),
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify'],
    )
    const ok = await globalThis.crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      verifyKey,
      toArrayBuffer(sig),
      toArrayBuffer(message),
    )
    expect(ok).toBe(true)
  })

  it('signs the registration device proof as a 64-byte ES256 (R||S) signature that verifies', async () => {
    const key = await new InMemorySecureKeyStore().resolveOrCreate(identity)
    const message = new TextEncoder().encode('{"idempotencyKey":"k"}')
    const sig = await key.signRegistrationDeviceAuthorization(message)
    expect(sig.length).toBe(64)

    const spki = fromBase64Url(await key.publicKeySpkiBase64Url())
    const verifyKey = await globalThis.crypto.subtle.importKey(
      'spki',
      toArrayBuffer(spki),
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify'],
    )
    const ok = await globalThis.crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      verifyKey,
      toArrayBuffer(sig),
      toArrayBuffer(message),
    )
    expect(ok).toBe(true)
  })

  it('derives distinct keys per environment namespace', async () => {
    const store = new InMemorySecureKeyStore()
    const sandbox = await store.resolveOrCreate({
      appId: 'app-123',
      environment: 'sandbox',
      clientEntityId: CLIENT_ENTITY_ID,
    })
    const production = await store.resolveOrCreate({
      appId: 'app-123',
      environment: 'production',
      clientEntityId: CLIENT_ENTITY_ID,
    })
    expect(sandbox).not.toBe(production)
    expect(await sandbox.thumbprint()).not.toBe(await production.thumbprint())
  })

  it('derives distinct keys per Owner namespace', async () => {
    const store = new InMemorySecureKeyStore()
    const ownerA = await store.resolveOrCreate(identity)
    const ownerB = await store.resolveOrCreate({
      ...identity,
      clientEntityId: '00000000-0000-4000-8000-000000000002',
    })
    expect(ownerA).not.toBe(ownerB)
    expect(await ownerA.thumbprint()).not.toBe(await ownerB.thumbprint())
  })

  it('fails closed when constructed in a production build', () => {
    const g = globalThis as { __DEV__?: boolean | undefined }
    const prev = g.__DEV__
    g.__DEV__ = false
    try {
      expect(() => new InMemorySecureKeyStore()).toThrow(/must not be used in\s+production/)
    } finally {
      g.__DEV__ = prev
    }
  })

  it('fails closed when no development marker is present', () => {
    const g = globalThis as {
      __DEV__?: boolean | undefined
      process?: { env?: { NODE_ENV?: string } }
    }
    const previousDev = g.__DEV__
    const environment = g.process?.env
    const previousNodeEnvironment = environment?.NODE_ENV
    g.__DEV__ = undefined
    if (environment !== undefined) delete environment.NODE_ENV
    try {
      expect(() => new InMemorySecureKeyStore()).toThrow(
        /requires an explicit development or test environment marker/,
      )
    } finally {
      g.__DEV__ = previousDev
      if (environment !== undefined) {
        if (previousNodeEnvironment === undefined) delete environment.NODE_ENV
        else environment.NODE_ENV = previousNodeEnvironment
      }
    }
  })
})
