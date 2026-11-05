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
import { toBase64Url } from '../crypto/base64url'
import {
  randomBytes,
  randomUuidV4,
  webCryptoRandomBytes,
  webCryptoRandomUuidV4,
} from '../crypto/random'
import { isDaaError } from '../errors'
import { isUuidV4 } from '../validation/uuid'
import type { DaaRegistrationNativeModule } from '../auth/daaRegistrationNative'

/**
 * The randomness source.
 *
 * Production `randomBytes` / `randomUuidV4` require the Expo module. Jest
 * injects a fake in `jest.setup.js`. Host WebCrypto is covered only through
 * the explicit `webCryptoRandom*` helpers.
 */

const requireNative = jest.mocked(requireOptionalNativeModule)
const defaultNativeImpl = requireNative.getMockImplementation()

afterEach(() => {
  requireNative.mockReset()
  if (defaultNativeImpl !== undefined) {
    requireNative.mockImplementation(defaultNativeImpl)
  }
})

function withHostCrypto<T>(replacement: Partial<Crypto> | undefined, operation: () => T): T {
  const host = globalThis as { crypto: Crypto | undefined }
  const original = host.crypto
  host.crypto = replacement as Crypto | undefined
  try {
    return operation()
  } finally {
    host.crypto = original
  }
}

function fakeRegistrationNative(
  overrides: Partial<DaaRegistrationNativeModule> = {},
): DaaRegistrationNativeModule {
  return {
    randomBytes: jest.fn((count: number) => toBase64Url(new Uint8Array(count).fill(7))),
    randomUuidV4: jest.fn(() => '0192d5c8-8f1a-4b2e-9c7d-3a5e2f6b1c04'),
    generateRegistrationFlowKey: jest.fn(() => 'flow-key-id'),
    registrationFlowPublicKeySpkiBase64Url: jest.fn(() => toBase64Url(new Uint8Array(91))),
    releaseRegistrationFlowKey: jest.fn(),
    signRegistrationAuthorization: jest.fn(() => toBase64Url(new Uint8Array(64))),
    verifyPrepareReceiptSignature: jest.fn(async () => false),
    ...overrides,
  }
}

describe('randomBytes', () => {
  it('fills the requested length from the native module', () => {
    expect(randomBytes(1)).toHaveLength(1)
    expect(randomBytes(32)).toHaveLength(32)
  })

  it('rejects a length that is not a positive integer', () => {
    for (const length of [0, -1, 1.5, Number.NaN]) {
      expect(() => randomBytes(length)).toThrow(/positive integer/)
    }
  })

  it('uses native DaaSecureRandom and does not call getRandomValues', () => {
    const native = fakeRegistrationNative()
    requireNative.mockImplementation((name: string) => (name === 'DaaRegistration' ? native : null))
    const getRandomValues = jest.fn()
    withHostCrypto({ getRandomValues }, () => {
      const bytes = randomBytes(32)
      expect(bytes).toHaveLength(32)
      expect(Array.from(bytes)).toEqual(Array(32).fill(7))
      expect(native.randomBytes).toHaveBeenCalledWith(32)
    })
    expect(getRandomValues).not.toHaveBeenCalled()
  })

  it('fails closed when the Expo module is absent, rather than using WebCrypto', () => {
    requireNative.mockImplementation(() => null)
    const getRandomValues = jest.fn()
    try {
      withHostCrypto({ getRandomValues }, () => randomBytes(32))
    } catch (err) {
      expect(isDaaError(err)).toBe(true)
      expect((err as Error).message).toMatch(/native DaaRegistration module is not available/)
      expect(getRandomValues).not.toHaveBeenCalled()
      return
    }
    throw new Error('expected randomBytes to fail closed without native module')
  })
})

describe('webCryptoRandomBytes', () => {
  it('fails closed with no getRandomValues, rather than falling back to Math.random', () => {
    for (const replacement of [undefined, {}, { getRandomValues: 'nope' as unknown as never }]) {
      try {
        withHostCrypto(replacement, () => webCryptoRandomBytes(32))
      } catch (err) {
        expect(isDaaError(err)).toBe(true)
        expect((err as Error).message).toMatch(/^DAA: crypto\.getRandomValues is required/)
        continue
      }
      throw new Error('expected webCryptoRandomBytes to fail closed')
    }
  })
})

describe('randomUuidV4', () => {
  it('passes the SDK guard the prepare idempotencyKey has to pass', () => {
    for (let i = 0; i < 64; i++) {
      expect(isUuidV4(randomUuidV4())).toBe(true)
    }
  })

  it('is fresh per call', () => {
    const uuids = new Set<string>()
    for (let i = 0; i < 64; i++) {
      uuids.add(randomUuidV4())
    }
    expect(uuids.size).toBe(64)
  })

  it('uses the native module UUID, not crypto.randomUUID', () => {
    const native = fakeRegistrationNative()
    requireNative.mockImplementation((name: string) => (name === 'DaaRegistration' ? native : null))
    const randomUUID = jest.fn(
      () =>
        '00000000-0000-4000-8000-000000000000' as `${string}-${string}-${string}-${string}-${string}`,
    )
    const uuid = withHostCrypto({ randomUUID }, () => randomUuidV4())
    expect(uuid).toBe('0192d5c8-8f1a-4b2e-9c7d-3a5e2f6b1c04')
    expect(randomUUID).not.toHaveBeenCalled()
  })

  it('fails closed when the Expo module is absent', () => {
    requireNative.mockImplementation(() => null)
    try {
      randomUuidV4()
    } catch (err) {
      expect(isDaaError(err)).toBe(true)
      expect((err as Error).message).toMatch(/native DaaRegistration module is not available/)
      return
    }
    throw new Error('expected randomUuidV4 to fail closed without native module')
  })
})

describe('webCryptoRandomUuidV4', () => {
  it('delegates to crypto.randomUUID instead of assembling a UUID here', () => {
    const canned = '0192d5c8-8f1a-4b2e-9c7d-3a5e2f6b1c04'
    const randomUUID = jest.fn(() => canned as `${string}-${string}-${string}-${string}-${string}`)

    const uuid = withHostCrypto({ randomUUID }, () => webCryptoRandomUuidV4())

    expect(randomUUID).toHaveBeenCalledTimes(1)
    expect(uuid).toBe(canned)
  })

  it('fails closed when the host provides no randomUUID', () => {
    for (const replacement of [undefined, {}, { randomUUID: 'nope' as unknown as never }]) {
      try {
        withHostCrypto(replacement, () => webCryptoRandomUuidV4())
      } catch (err) {
        expect(isDaaError(err)).toBe(true)
        expect((err as Error).message).toMatch(/^DAA: crypto\.randomUUID is required/)
        continue
      }
      throw new Error('expected webCryptoRandomUuidV4 to fail closed')
    }
  })

  it('fails closed when a polyfill returns a malformed or non-v4 value', () => {
    const bad = [
      '',
      'not-a-uuid',
      '0192d5c8-8f1a-1b2e-9c7d-3a5e2f6b1c04',
      '0192d5c8-8f1a-4b2e-0c7d-3a5e2f6b1c04',
      '0192d5c88f1a4b2e9c7d3a5e2f6b1c04',
    ]
    for (const value of bad) {
      const randomUUID = jest.fn(() => value as `${string}-${string}-${string}-${string}-${string}`)
      try {
        withHostCrypto({ randomUUID }, () => webCryptoRandomUuidV4())
      } catch (err) {
        expect(isDaaError(err)).toBe(true)
        expect((err as Error).message).toMatch(/did not return an RFC 4122 version 4 UUID/)
        continue
      }
      throw new Error(`expected webCryptoRandomUuidV4 to reject ${JSON.stringify(value)}`)
    }
  })
})
