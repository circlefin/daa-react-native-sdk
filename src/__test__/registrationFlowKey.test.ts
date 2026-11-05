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
import {
  defaultRegistrationFlowKeyProvider,
  nativeRegistrationFlowKeyProvider,
  webCryptoRegistrationFlowKeyProvider,
} from '../auth/RegistrationFlowKey'
import type { DaaRegistrationNativeModule } from '../auth/daaRegistrationNative'
import { fromBase64Url, toBase64Url } from '../crypto/base64url'
import { isDaaError } from '../errors'
import { InMemorySecureKeyStore } from '../securekey/InMemorySecureKey'

/**
 * The ephemeral registration-flow key.
 *
 * These tests are as much about what the key is NOT as what it is: it is not an
 * AuthKey, it does not come from `SecureKeyStore`, it exposes no generic
 * signing member,
 * and it is fresh per attempt. Those are the properties the login contract relies
 * on: Prepare sends the ephemeral public key, never an AuthKey public key.
 */

const BASE64URL_122 = /^[A-Za-z0-9_-]{122}$/

async function withoutWebCrypto<T>(operation: () => Promise<T>): Promise<T> {
  const host = globalThis as { crypto: Crypto | undefined }
  const original = host.crypto
  // `getRandomValues` stays available; only `subtle` is removed, which is the
  // real Hermes shape once a random-only polyfill is installed.
  host.crypto = { getRandomValues: original?.getRandomValues.bind(original) } as Crypto
  try {
    return await operation()
  } finally {
    host.crypto = original
  }
}

describe('webCryptoRegistrationFlowKeyProvider', () => {
  it('exports the 122-character unpadded Base64URL P-256 SPKI the contract pins', async () => {
    const key = await webCryptoRegistrationFlowKeyProvider().generate()
    const spki = await key.publicKeySpkiBase64Url()

    expect(spki).toMatch(BASE64URL_122)
    const bytes = fromBase64Url(spki)
    expect(bytes).toHaveLength(91)
    // Uncompressed point marker at the fixed P-256 SPKI offset. A compressed
    // point would be 59 bytes and is rejected by the length check above.
    expect(bytes[26]).toBe(0x04)
  })

  it('mints a distinct key per attempt', async () => {
    const provider = webCryptoRegistrationFlowKeyProvider()
    const first = await (await provider.generate()).publicKeySpkiBase64Url()
    const second = await (await provider.generate()).publicKeySpkiBase64Url()
    expect(first).not.toBe(second)
  })

  it('is stable for one key', async () => {
    const key = await webCryptoRegistrationFlowKeyProvider().generate()
    expect(await key.publicKeySpkiBase64Url()).toBe(await key.publicKeySpkiBase64Url())
  })

  it('signs exact bytes with ES256 JOSE R||S and does not expose a generic sign', async () => {
    const key = await webCryptoRegistrationFlowKeyProvider().generate()
    const surface = key as unknown as Record<string, unknown>
    for (const name of ['sign', 'privateKey', 'thumbprint', 'keyPair']) {
      expect(surface[name]).toBeUndefined()
    }
    expect(Object.getOwnPropertyNames(Object.getPrototypeOf(key)).sort()).toEqual([
      'constructor',
      'publicKeySpkiBase64Url',
      'release',
      'signExactBytes',
    ])
    expect(Object.isFrozen(key)).toBe(true)
    const signature = await key.signExactBytes(new TextEncoder().encode('abc'))
    expect(signature).toHaveLength(64)
  })

  it('is not an AuthKey: no SPKI it produces is one the secure-key store would resolve', async () => {
    // Not a cryptographic claim — two independently generated P-256 keys never
    // collide. The point is structural: the flow key comes from its own provider,
    // and nothing in this path constructs an identity, an alias, or a store.
    const flowKey = await webCryptoRegistrationFlowKeyProvider().generate()
    const authKey = await new InMemorySecureKeyStore().resolveOrCreate({
      appId: 'app-123',
      environment: 'sandbox',
      clientEntityId: '00000000-0000-4000-8000-000000000001',
    })
    expect(await flowKey.publicKeySpkiBase64Url()).not.toBe(await authKey.publicKeySpkiBase64Url())
    // And unlike an AuthKey, the flow key has no registration state at all.
    expect((flowKey as unknown as Record<string, unknown>).resolution).toBeUndefined()
    expect((flowKey as unknown as Record<string, unknown>).acknowledgeRegistration).toBeUndefined()
  })

  it('fails closed when the host has no crypto.subtle, rather than weakening key generation', async () => {
    await withoutWebCrypto(async () => {
      const provider = webCryptoRegistrationFlowKeyProvider()
      try {
        await provider.generate()
      } catch (err) {
        expect(isDaaError(err)).toBe(true)
        if (isDaaError(err)) {
          expect(err.detail.kind).toBe('contract_violation')
          expect(err.message).toMatch(/crypto\.subtle is required/)
        }
        return
      }
      throw new Error('expected registration-flow key generation to fail closed')
    })
  })
})

const requireNative = jest.mocked(requireOptionalNativeModule)
const defaultNativeImpl = requireNative.getMockImplementation()

afterEach(() => {
  requireNative.mockReset()
  if (defaultNativeImpl !== undefined) {
    requireNative.mockImplementation(defaultNativeImpl)
  }
})

function fakeSpki(distinct: number): string {
  const bytes = new Uint8Array(91)
  bytes[26] = 0x04
  bytes[90] = distinct
  return toBase64Url(bytes)
}

function fakeSignature(distinct: number): string {
  const bytes = new Uint8Array(64)
  bytes[63] = distinct
  return toBase64Url(bytes)
}

function fakeRegistrationNative(): DaaRegistrationNativeModule {
  const exported = new Map<string, string>()
  let next = 0
  return {
    randomBytes: jest.fn(),
    randomUuidV4: jest.fn(),
    generateRegistrationFlowKey: jest.fn(() => {
      const id = `flow-${next}`
      exported.set(id, fakeSpki(next))
      next += 1
      return id
    }),
    registrationFlowPublicKeySpkiBase64Url: jest.fn((id: string) => {
      const spki = exported.get(id)
      if (spki === undefined) {
        throw new Error(`no flow key ${id}`)
      }
      return spki
    }),
    // Models the native cache: release really drops it, so a released key
    // cannot still export. A no-op fake here would let a missing release pass.
    releaseRegistrationFlowKey: jest.fn((id: string) => {
      exported.delete(id)
    }),
    // Models the typed native sign: it does not decode or reinterpret the
    // signing input, it just proves it received the exact Base64URL bytes by
    // handing back a deterministic, distinguishable fake signature.
    signRegistrationAuthorization: jest.fn((id: string, signingInputBase64Url: string) => {
      if (!exported.has(id)) {
        throw new Error(`no flow key ${id}`)
      }
      void signingInputBase64Url
      return fakeSignature(next)
    }),
    verifyPrepareReceiptSignature: jest.fn(async () => false),
  }
}

describe('registration-flow key release', () => {
  it('drops the native key so its private half stops being held', async () => {
    const native = fakeRegistrationNative()
    const key = await nativeRegistrationFlowKeyProvider(native).generate()
    await key.publicKeySpkiBase64Url()

    await key.release()

    expect(native.releaseRegistrationFlowKey).toHaveBeenCalledTimes(1)
    // The native cache is process-lifetime, so "released" has to mean the key
    // is actually gone, not merely that a method was called. Exporting after
    // release must fail rather than return a stale value.
    await expect(key.publicKeySpkiBase64Url()).rejects.toThrow()
  })

  it('is idempotent, so a finally block can release unconditionally', async () => {
    const native = fakeRegistrationNative()
    const key = await nativeRegistrationFlowKeyProvider(native).generate()

    await key.release()
    await expect(key.release()).resolves.toBeUndefined()
  })

  it('tolerates a host module that predates the release function', async () => {
    // An older linked module simply has no releaseRegistrationFlowKey. Cleanup
    // must not throw over that; the caller is usually already in a finally.
    const native = fakeRegistrationNative()
    delete (native as { releaseRegistrationFlowKey?: unknown }).releaseRegistrationFlowKey
    const key = await nativeRegistrationFlowKeyProvider(native).generate()

    await expect(key.release()).resolves.toBeUndefined()
  })

  it('has a release on the WebCrypto stand-in too, so one interface covers both', async () => {
    const key = await webCryptoRegistrationFlowKeyProvider().generate()
    await expect(key.release()).resolves.toBeUndefined()
    // Unlike the native key, nothing is freed, so export still works.
    expect(await key.publicKeySpkiBase64Url()).toHaveLength(122)
  })
})

describe('nativeRegistrationFlowKeyProvider', () => {
  it('exports the 122-character unpadded Base64URL P-256 SPKI the contract pins', async () => {
    const native = fakeRegistrationNative()
    const key = await nativeRegistrationFlowKeyProvider(native).generate()
    const spki = await key.publicKeySpkiBase64Url()

    expect(spki).toMatch(BASE64URL_122)
    const bytes = fromBase64Url(spki)
    expect(bytes).toHaveLength(91)
    expect(bytes[26]).toBe(0x04)
    expect(native.generateRegistrationFlowKey).toHaveBeenCalledTimes(1)
    expect(native.registrationFlowPublicKeySpkiBase64Url).toHaveBeenCalledWith('flow-0')
  })

  it('mints a distinct key per attempt', async () => {
    const native = fakeRegistrationNative()
    const provider = nativeRegistrationFlowKeyProvider(native)
    const first = await (await provider.generate()).publicKeySpkiBase64Url()
    const second = await (await provider.generate()).publicKeySpkiBase64Url()
    expect(first).not.toBe(second)
  })

  it('is stable for one key', async () => {
    const native = fakeRegistrationNative()
    const key = await nativeRegistrationFlowKeyProvider(native).generate()
    expect(await key.publicKeySpkiBase64Url()).toBe(await key.publicKeySpkiBase64Url())
  })

  it('signs exact bytes through the native typed sign and does not expose a generic sign', async () => {
    const native = fakeRegistrationNative()
    const key = await nativeRegistrationFlowKeyProvider(native).generate()
    const surface = key as unknown as Record<string, unknown>
    for (const name of ['sign', 'privateKey', 'thumbprint', 'keyPair']) {
      expect(surface[name]).toBeUndefined()
    }
    expect(Object.getOwnPropertyNames(Object.getPrototypeOf(key)).sort()).toEqual([
      'constructor',
      'publicKeySpkiBase64Url',
      'release',
      'signExactBytes',
    ])
    expect(Object.isFrozen(key)).toBe(true)

    const message = new TextEncoder().encode('{"idempotencyKey":"k"}')
    const signature = await key.signExactBytes(message)

    expect(signature).toHaveLength(64)
    expect(native.signRegistrationAuthorization).toHaveBeenCalledTimes(1)
    expect(native.signRegistrationAuthorization).toHaveBeenCalledWith(
      'flow-0',
      toBase64Url(message),
    )
  })

  it('surfaces a contract violation when the native sign call fails', async () => {
    const native = fakeRegistrationNative()
    const failing: DaaRegistrationNativeModule = {
      ...native,
      signRegistrationAuthorization: jest.fn(() => {
        throw new Error('native signing failed')
      }),
    }
    const key = await nativeRegistrationFlowKeyProvider(failing).generate()
    await expect(key.signExactBytes(new Uint8Array([1]))).rejects.toMatchObject({
      detail: { kind: 'contract_violation' },
    })
  })

  it('keeps the private key behind the native handle — JS only holds an id', async () => {
    const native = fakeRegistrationNative()
    const key = await nativeRegistrationFlowKeyProvider(native).generate()
    expect(JSON.stringify(key)).toBe('{}')
  })
})

describe('defaultRegistrationFlowKeyProvider', () => {
  it('uses the native Expo module when it is present', async () => {
    const native = fakeRegistrationNative()
    requireNative.mockImplementation((name: string) => (name === 'DaaRegistration' ? native : null))
    const key = await defaultRegistrationFlowKeyProvider().generate()
    await key.publicKeySpkiBase64Url()
    expect(native.generateRegistrationFlowKey).toHaveBeenCalledTimes(1)
  })

  it('fails closed when the Expo module is absent, rather than using WebCrypto', async () => {
    requireNative.mockImplementation(() => null)
    const provider = defaultRegistrationFlowKeyProvider()
    try {
      await provider.generate()
    } catch (err) {
      expect(isDaaError(err)).toBe(true)
      if (isDaaError(err)) {
        expect(err.message).toMatch(/native DaaRegistration module is not available/)
      }
      return
    }
    throw new Error('expected default provider to fail closed without native module')
  })
})
