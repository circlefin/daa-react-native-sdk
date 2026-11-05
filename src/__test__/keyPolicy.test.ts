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

import { readFileSync } from 'node:fs'

import { requireOptionalNativeModule } from 'expo-modules-core'

import { DaaClient } from '../DaaClient'
import { assertDeviceKeyPolicy, DEVICE_KEY_POLICY, isRequiredDeviceKeyPolicy } from '../config'
import { isDaaError } from '../errors'
import { resolveNativeBridge } from '../securekey/resolveNativeBridge'
import type { DaaTransport } from '../transport/DaaTransport'

const transport: DaaTransport = {
  async send() {
    return { status: 200, headers: {}, bodyBytes: null }
  },
}

const weakerPolicy = Object.freeze({
  hardwareBacked: false,
  userVerification: 'REQUIRED_FOR_EACH_SIGNATURE',
})

function sdkConfig() {
  return {
    appId: 'app-123',
    environment: 'sandbox' as const,
    transport,
    keyPolicy: DEVICE_KEY_POLICY,
  }
}

function readUtf8(relativeFromTest: string): string {
  return new TextDecoder().decode(readFileSync(`${__dirname}/${relativeFromTest}`))
}

describe('DeviceKeyPolicy closed set', () => {
  it('accepts only the required singleton policy', () => {
    expect(assertDeviceKeyPolicy(DEVICE_KEY_POLICY)).toBe(DEVICE_KEY_POLICY)
    expect(isRequiredDeviceKeyPolicy(DEVICE_KEY_POLICY)).toBe(true)
    expect(assertDeviceKeyPolicy({ ...DEVICE_KEY_POLICY, extra: 1 })).toBe(DEVICE_KEY_POLICY)
  })

  it('rejects a missing or weaker policy', () => {
    expect(() => assertDeviceKeyPolicy(undefined)).toThrow(/keyPolicy is required/)
    expect(() => assertDeviceKeyPolicy(null)).toThrow(/keyPolicy is required/)
    expect(() => assertDeviceKeyPolicy(weakerPolicy)).toThrow(/hardware-backed/)
    expect(() =>
      assertDeviceKeyPolicy({
        hardwareBacked: true,
        userVerification: 'OPTIONAL',
      }),
    ).toThrow(/REQUIRED_FOR_EACH_SIGNATURE/)
    expect(isRequiredDeviceKeyPolicy(weakerPolicy)).toBe(false)
  })
})

describe('DaaClient keyPolicy', () => {
  it('rejects construction without the closed-set policy', () => {
    expect(
      () =>
        new DaaClient({
          appId: 'app-123',
          environment: 'sandbox',
          transport,
        } as never),
    ).toThrow(/keyPolicy is required/)
  })

  it('rejects a weaker policy at construction', () => {
    expect(
      () =>
        new DaaClient({
          ...sdkConfig(),
          keyPolicy: weakerPolicy as never,
        }),
    ).toThrow(/hardware-backed/)
  })

  it('stores the canonical frozen policy', () => {
    const client = new DaaClient(sdkConfig())
    expect(client.keyPolicy).toBe(DEVICE_KEY_POLICY)
    expect(Object.isFrozen(client.keyPolicy)).toBe(true)
  })
})

describe('native declaredKeyPolicy', () => {
  const requireNative = jest.mocked(requireOptionalNativeModule)
  const originalNative = requireNative.getMockImplementation()

  afterEach(() => {
    requireNative.mockReset()
    if (originalNative !== undefined) {
      requireNative.mockImplementation(originalNative)
    }
  })

  function mockSecureKey(declared: unknown) {
    requireNative.mockImplementation((name) => {
      if (name !== 'DaaSecureKey') {
        return null
      }
      return {
        declaredKeyPolicy: typeof declared === 'function' ? declared : () => declared,
        resolveOrCreate: jest.fn(),
        publicKeySpkiBase64Url: jest.fn(),
        acknowledgeRegistration: jest.fn(),
      }
    })
  }

  it('constructs when the native module declares the configured policy', () => {
    mockSecureKey(DEVICE_KEY_POLICY)
    const client = new DaaClient(sdkConfig())
    expect(client.keyPolicy).toBe(DEVICE_KEY_POLICY)
    expect(() => resolveNativeBridge()).not.toThrow()
  })

  it('fails closed when the native module declares a weaker policy', () => {
    mockSecureKey(weakerPolicy)
    const err = (() => {
      try {
        new DaaClient(sdkConfig())
        return undefined
      } catch (caught: unknown) {
        return caught
      }
    })()
    expect(isDaaError(err) && err.detail.kind === 'contract_violation').toBe(true)
    expect(String(err)).toMatch(/does not match the configured DeviceKeyPolicy/)

    expect(() => resolveNativeBridge()).toThrow(/does not match the configured DeviceKeyPolicy/)
  })

  it('fails closed when the native module omits the capability query', () => {
    requireNative.mockImplementation((name) => {
      if (name !== 'DaaSecureKey') {
        return null
      }
      return {
        resolveOrCreate: jest.fn(),
        publicKeySpkiBase64Url: jest.fn(),
        acknowledgeRegistration: jest.fn(),
      }
    })
    expect(() => new DaaClient(sdkConfig())).toThrow(/did not declare a DeviceKeyPolicy/)
    expect(() => resolveNativeBridge()).toThrow(/did not declare a DeviceKeyPolicy/)
  })
})

// Reads the native source as text and greps for literal substrings, rather
// than compiling Swift/Kotlin (this suite is Node-only). Intentionally
// brittle to the exact strings below: a Swift/Kotlin formatter reflowing
// these lines without changing their meaning would break this test, and
// that is an acceptable, expected failure mode for a check whose entire job
// is pinning the literal source, not a bug to work around.
describe('native source pin', () => {
  it('Expo DaaSecureKey modules declare the required DeviceKeyPolicy', () => {
    const swift = readUtf8('../../ios/DaaSecureKeyModule.swift')
    const kotlin = readUtf8(
      '../../android/src/main/java/com/circle/daa/reactnative/DaaSecureKeyModule.kt',
    )
    for (const source of [swift, kotlin]) {
      expect(source).toContain('declaredKeyPolicy')
      expect(source).toContain('REQUIRED_FOR_EACH_SIGNATURE')
    }
    expect(swift).toContain('"hardwareBacked": true')
    expect(kotlin).toContain('"hardwareBacked" to true')
  })
})
