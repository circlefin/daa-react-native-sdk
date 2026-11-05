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
import { DEVICE_KEY_POLICY } from '../config'
import { fromBase64Url, toBase64Url } from '../crypto/base64url'
import { toArrayBuffer } from '../crypto/bytes'
import { DaaError, isDaaError } from '../errors'
import type { NativeSecureKeyBridge } from '../securekey/NativeSecureKeyBridge'
import { NativeSecureKeyStore } from '../securekey/NativeSecureKey'
import { resolveNativeBridge } from '../securekey/resolveNativeBridge'

// `expo-modules-core` is mocked globally in jest.setup.js (returns null, so the
// native module is always absent in Node). The import above picks up that mock;
// `jest.mocked()` below re-points it per test.

// A WebCrypto-backed stand-in for the platform native module. It exercises the
// exact bridge contract (Base64URL in/out, one non-exportable P-256 key per
// alias) without device hardware, so it validates NativeSecureKeyStore's
// delegation and byte transport end-to-end. The thumbprint is derived in TS, so
// the bridge does not implement it.
class FakeNativeBridge implements NativeSecureKeyBridge {
  private readonly keys = new Map<string, CryptoKeyPair>()
  private readonly acknowledged = new Set<string>()
  public resolveCalls = 0

  private subtle(): SubtleCrypto {
    return globalThis.crypto.subtle
  }

  private pair(alias: string): CryptoKeyPair {
    const kp = this.keys.get(alias)
    if (!kp) throw new Error(`no key for ${alias}`)
    return kp
  }

  async resolveOrCreate(alias: string): Promise<'created' | 'existing'> {
    this.resolveCalls += 1
    if (!this.keys.has(alias)) {
      const kp = (await this.subtle().generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
        'sign',
        'verify',
      ])) as CryptoKeyPair
      this.keys.set(alias, kp)
      return 'created'
    }
    // A key that exists but was never acknowledged still resolves 'created' —
    // this mirrors the native SDK contract, where only a durable
    // acknowledgement yields 'existing'.
    return this.acknowledged.has(alias) ? 'existing' : 'created'
  }

  async acknowledgeRegistration(alias: string): Promise<void> {
    this.pair(alias) // native rejects an ack for a key that was never resolved
    this.acknowledged.add(alias)
  }

  async publicKeySpkiBase64Url(alias: string): Promise<string> {
    const spki = await this.subtle().exportKey('spki', this.pair(alias).publicKey)
    return toBase64Url(new Uint8Array(spki))
  }

  async sign(alias: string, messageBase64Url: string): Promise<string> {
    const signature = await this.subtle().sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      this.pair(alias).privateKey,
      toArrayBuffer(fromBase64Url(messageBase64Url)),
    )
    return toBase64Url(new Uint8Array(signature))
  }

  registrationSignCalls = 0

  async signRegistrationDeviceAuthorization(
    alias: string,
    messageBase64Url: string,
  ): Promise<string> {
    // A distinct bridge method from `sign`, tracked separately so a test can
    // assert which one a caller actually reached, even though this fake signs
    // with the same underlying key either way.
    this.registrationSignCalls += 1
    return this.sign(alias, messageBase64Url)
  }
}

const CLIENT_ENTITY_ID = '00000000-0000-4000-8000-000000000001'

const identity = {
  appId: 'app-123',
  environment: 'sandbox',
  clientEntityId: CLIENT_ENTITY_ID,
} as const

describe('NativeSecureKeyStore', () => {
  it('returns the same installation key for the same identity', async () => {
    const store = new NativeSecureKeyStore(new FakeNativeBridge())
    const a = await store.resolveOrCreate(identity)
    const b = await store.resolveOrCreate(identity)
    expect(a).toBe(b)
  })

  it('reports created until acknowledgement, then existing, and still signs while created', async () => {
    const store = new NativeSecureKeyStore(new FakeNativeBridge())
    const key = await store.resolveOrCreate(identity)
    expect(key.resolution()).toBe('created')
    const sig = await key.signExactBytes(new Uint8Array([1, 2, 3]))
    expect(sig.length).toBe(64)

    await key.acknowledgeRegistration()
    expect(key.resolution()).toBe('existing')
    await key.acknowledgeRegistration()
    expect(key.resolution()).toBe('existing')
  })

  it('reports created again for an unacknowledged key resolved by a fresh store', async () => {
    // The durable state lives in the bridge (native), not in the store's
    // in-process handle cache. A second store over the same bridge is what a
    // relaunch looks like: an existing-but-unacknowledged key must NOT be
    // reported as 'existing'.
    const bridge = new FakeNativeBridge()
    const first = await new NativeSecureKeyStore(bridge).resolveOrCreate(identity)
    expect(first.resolution()).toBe('created')

    const afterRelaunch = await new NativeSecureKeyStore(bridge).resolveOrCreate(identity)
    expect(afterRelaunch.resolution()).toBe('created')

    await afterRelaunch.acknowledgeRegistration()
    const afterAck = await new NativeSecureKeyStore(bridge).resolveOrCreate(identity)
    expect(afterAck.resolution()).toBe('existing')
  })

  it('does not re-enter native acknowledgement once the handle is existing', async () => {
    let acks = 0
    const counting: NativeSecureKeyBridge = {
      async resolveOrCreate() {
        return 'created'
      },
      async acknowledgeRegistration() {
        acks += 1
      },
      async publicKeySpkiBase64Url() {
        return toBase64Url(new Uint8Array(91))
      },
      async sign() {
        return toBase64Url(new Uint8Array(64))
      },
      async signRegistrationDeviceAuthorization() {
        return toBase64Url(new Uint8Array(64))
      },
    }
    const key = await new NativeSecureKeyStore(counting).resolveOrCreate(identity)
    await key.acknowledgeRegistration()
    await key.acknowledgeRegistration()
    await key.acknowledgeRegistration()
    expect(acks).toBe(1)
    expect(key.resolution()).toBe('existing')
  })

  it('de-duplicates concurrent acknowledgement to a single native call', async () => {
    let acks = 0
    let release: (() => void) | undefined
    const gate = new Promise<void>((resolve) => {
      release = resolve
    })
    const slow: NativeSecureKeyBridge = {
      async resolveOrCreate() {
        return 'created'
      },
      async acknowledgeRegistration() {
        acks += 1
        await gate // hold the call open so both callers overlap
      },
      async publicKeySpkiBase64Url() {
        return toBase64Url(new Uint8Array(91))
      },
      async sign() {
        return toBase64Url(new Uint8Array(64))
      },
      async signRegistrationDeviceAuthorization() {
        return toBase64Url(new Uint8Array(64))
      },
    }
    const key = await new NativeSecureKeyStore(slow).resolveOrCreate(identity)
    const both = Promise.all([key.acknowledgeRegistration(), key.acknowledgeRegistration()])
    release?.()
    await both
    expect(acks).toBe(1)
    expect(key.resolution()).toBe('existing')
  })

  it('retries acknowledgement after a failure rather than memoizing it', async () => {
    let calls = 0
    const flakyAck: NativeSecureKeyBridge = {
      async resolveOrCreate() {
        return 'created'
      },
      async acknowledgeRegistration() {
        calls += 1
        if (calls === 1) throw new Error('kSecUseAuthenticationUI -25293')
      },
      async publicKeySpkiBase64Url() {
        return toBase64Url(new Uint8Array(91))
      },
      async sign() {
        return toBase64Url(new Uint8Array(64))
      },
      async signRegistrationDeviceAuthorization() {
        return toBase64Url(new Uint8Array(64))
      },
    }
    const key = await new NativeSecureKeyStore(flakyAck).resolveOrCreate(identity)
    await expect(key.acknowledgeRegistration()).rejects.toBeInstanceOf(DaaError)
    expect(key.resolution()).toBe('created')
    // The failed attempt is not memoized: a retry reaches native and succeeds.
    await expect(key.acknowledgeRegistration()).resolves.toBeUndefined()
    expect(calls).toBe(2)
    expect(key.resolution()).toBe('existing')
  })

  it('keeps the handle created when native acknowledgement fails, and maps the error', async () => {
    const failing: NativeSecureKeyBridge = {
      async resolveOrCreate() {
        return 'created'
      },
      async acknowledgeRegistration() {
        throw new Error('SecItemUpdate OSStatus -25300')
      },
      async publicKeySpkiBase64Url() {
        return toBase64Url(new Uint8Array(91))
      },
      async sign() {
        return toBase64Url(new Uint8Array(64))
      },
      async signRegistrationDeviceAuthorization() {
        return toBase64Url(new Uint8Array(64))
      },
    }
    const key = await new NativeSecureKeyStore(failing).resolveOrCreate(identity)
    const err = await key.acknowledgeRegistration().catch((e: unknown) => e)
    expect(err).toBeInstanceOf(DaaError)
    expect((err as DaaError).detail.kind).toBe('contract_violation')
    expect((err as DaaError).message).not.toMatch(/OSStatus/) // raw native text suppressed
    // Fail closed: a failed ack must not present the key as registered.
    expect(key.resolution()).toBe('created')
  })

  it('rejects a native resolution other than created or existing', async () => {
    const bad: NativeSecureKeyBridge = {
      async resolveOrCreate() {
        return 'maybe' as never
      },
      async acknowledgeRegistration() {},
      async publicKeySpkiBase64Url() {
        return toBase64Url(new Uint8Array(91))
      },
      async sign() {
        return toBase64Url(new Uint8Array(64))
      },
      async signRegistrationDeviceAuthorization() {
        return toBase64Url(new Uint8Array(64))
      },
    }
    await expect(new NativeSecureKeyStore(bad).resolveOrCreate(identity)).rejects.toThrow(
      /created or existing/,
    )
  })

  it('delegates signing across the bridge and yields a verifiable ES256 R||S', async () => {
    const store = new NativeSecureKeyStore(new FakeNativeBridge())
    const key = await store.resolveOrCreate(identity)
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

  it('routes signRegistrationDeviceAuthorization through a distinct bridge call from signExactBytes', async () => {
    const bridge = new FakeNativeBridge()
    const store = new NativeSecureKeyStore(bridge)
    const key = await store.resolveOrCreate(identity)
    const message = new TextEncoder().encode('{"idempotencyKey":"k"}')

    const sig = await key.signRegistrationDeviceAuthorization(message)
    expect(sig.length).toBe(64)
    expect(bridge.registrationSignCalls).toBe(1)

    // The two AuthKey methods are not interchangeable: signExactBytes must not
    // have reached the registration bridge call, and vice versa.
    await key.signExactBytes(message)
    expect(bridge.registrationSignCalls).toBe(1)
  })

  it('derives distinct thumbprints per environment namespace', async () => {
    const store = new NativeSecureKeyStore(new FakeNativeBridge())
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
    expect(await sandbox.thumbprint()).not.toBe(await production.thumbprint())
  })

  it('derives distinct thumbprints per Owner namespace', async () => {
    const store = new NativeSecureKeyStore(new FakeNativeBridge())
    const ownerA = await store.resolveOrCreate(identity)
    const ownerB = await store.resolveOrCreate({
      ...identity,
      clientEntityId: '00000000-0000-4000-8000-000000000002',
    })
    expect(await ownerA.thumbprint()).not.toBe(await ownerB.thumbprint())
  })

  it('maps a native failure to a DaaError without leaking its text, and evicts it', async () => {
    let calls = 0
    const flaky: NativeSecureKeyBridge = {
      async resolveOrCreate() {
        calls += 1
        if (calls === 1) throw new Error('SecItemCopyMatching OSStatus -25300')
        return 'existing'
      },
      async acknowledgeRegistration() {},
      async publicKeySpkiBase64Url() {
        return toBase64Url(new Uint8Array(91))
      },
      async sign() {
        return toBase64Url(new Uint8Array(64))
      },
      async signRegistrationDeviceAuthorization() {
        return toBase64Url(new Uint8Array(64))
      },
    }
    const store = new NativeSecureKeyStore(flaky)
    const err = await store.resolveOrCreate(identity).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(DaaError)
    expect((err as DaaError).detail.kind).toBe('contract_violation')
    expect((err as DaaError).message).not.toMatch(/OSStatus/) // raw native text suppressed
    // Not memoized: a second call succeeds.
    await expect(store.resolveOrCreate(identity)).resolves.toBeDefined()
    expect(calls).toBe(2)
  })

  it('de-duplicates concurrent resolution to a single native call', async () => {
    const bridge = new FakeNativeBridge()
    const store = new NativeSecureKeyStore(bridge)
    const [a, b] = await Promise.all([
      store.resolveOrCreate(identity),
      store.resolveOrCreate(identity),
    ])
    expect(a).toBe(b)
    expect(bridge.resolveCalls).toBe(1)
  })

  it('rejects a native signature that is not 64-byte R||S', async () => {
    const derLike: NativeSecureKeyBridge = {
      async resolveOrCreate() {
        return 'existing'
      },
      async acknowledgeRegistration() {},
      async publicKeySpkiBase64Url() {
        return toBase64Url(new Uint8Array(91))
      },
      // 70 bytes — what a native module returns if it forgets DER -> R||S.
      async sign() {
        return toBase64Url(new Uint8Array(70))
      },
      async signRegistrationDeviceAuthorization() {
        return toBase64Url(new Uint8Array(64))
      },
    }
    const key = await new NativeSecureKeyStore(derLike).resolveOrCreate(identity)
    await expect(key.signExactBytes(new Uint8Array([1, 2, 3]))).rejects.toThrow(/64 bytes/)
  })

  it('rejects a public key that is not a 91-byte P-256 SPKI', async () => {
    const rawPoint: NativeSecureKeyBridge = {
      async resolveOrCreate() {
        return 'existing'
      },
      async acknowledgeRegistration() {},
      // 65-byte uncompressed point instead of the 91-byte SPKI.
      async publicKeySpkiBase64Url() {
        return toBase64Url(new Uint8Array(65))
      },
      async sign() {
        return toBase64Url(new Uint8Array(64))
      },
      async signRegistrationDeviceAuthorization() {
        return toBase64Url(new Uint8Array(64))
      },
    }
    const key = await new NativeSecureKeyStore(rawPoint).resolveOrCreate(identity)
    await expect(key.publicKeySpkiBase64Url()).rejects.toThrow(/91 bytes/)
  })

  it('rejects a 91-byte public key that is not an uncompressed-point SPKI (thumbprint path)', async () => {
    const notSpki: NativeSecureKeyBridge = {
      async resolveOrCreate() {
        return 'existing'
      },
      async acknowledgeRegistration() {},
      // Right length, but byte 26 !== 0x04 — passes decodeExact, fails jkt.
      async publicKeySpkiBase64Url() {
        return toBase64Url(new Uint8Array(91))
      },
      async sign() {
        return toBase64Url(new Uint8Array(64))
      },
      async signRegistrationDeviceAuthorization() {
        return toBase64Url(new Uint8Array(64))
      },
    }
    const key = await new NativeSecureKeyStore(notSpki).resolveOrCreate(identity)
    const err = await key.thumbprint().catch((e: unknown) => e)
    expect(err).toBeInstanceOf(DaaError)
    expect((err as DaaError).detail.kind).toBe('contract_violation')
  })

  it('rejects a native value that is not valid Base64URL', async () => {
    const bad: NativeSecureKeyBridge = {
      async resolveOrCreate() {
        return 'existing'
      },
      async acknowledgeRegistration() {},
      async publicKeySpkiBase64Url() {
        return 'A' // length % 4 === 1 — impossible for Base64URL
      },
      async sign() {
        return toBase64Url(new Uint8Array(64))
      },
      async signRegistrationDeviceAuthorization() {
        return toBase64Url(new Uint8Array(64))
      },
    }
    const key = await new NativeSecureKeyStore(bad).resolveOrCreate(identity)
    await expect(key.publicKeySpkiBase64Url()).rejects.toThrow(/not valid Base64URL/)
  })

  it('rejects an appId that is not a valid key namespace', async () => {
    const store = new NativeSecureKeyStore(new FakeNativeBridge())
    await expect(
      store.resolveOrCreate({
        appId: '',
        environment: 'sandbox',
        clientEntityId: CLIENT_ENTITY_ID,
      }),
    ).rejects.toThrow(/appId must match/)
  })
})

describe('resolveNativeBridge', () => {
  const requireNative = jest.mocked(requireOptionalNativeModule)

  function nativeModule(
    overrides: {
      declaredKeyPolicy?: () => unknown
      resolveOrCreate?: jest.Mock
      publicKeySpkiBase64Url?: jest.Mock
      acknowledgeRegistration?: jest.Mock
      signDeviceAuthorization?: jest.Mock
      signRegistrationDeviceAuthorization?: jest.Mock
    } = {},
  ) {
    return {
      declaredKeyPolicy: () => DEVICE_KEY_POLICY,
      resolveOrCreate: jest.fn(async () => 'created'),
      publicKeySpkiBase64Url: jest.fn(async () => toBase64Url(new Uint8Array(91))),
      acknowledgeRegistration: jest.fn(async () => undefined),
      ...overrides,
    }
  }

  afterEach(() => {
    requireNative.mockReset()
    requireNative.mockImplementation(() => null)
  })

  it('fails closed when the native module is absent', () => {
    requireNative.mockReturnValue(null)
    expect(() => resolveNativeBridge()).toThrow(/not available/)
  })

  it('parses a dotted appId from the right and delegates resolve and SPKI', async () => {
    const native = nativeModule()
    requireNative.mockReturnValue(native)

    const bridge = resolveNativeBridge()
    await expect(bridge.resolveOrCreate('acme.staging.sandbox')).resolves.toBe('created')
    expect(native.resolveOrCreate).toHaveBeenCalledWith('acme.staging', 'sandbox')

    await expect(bridge.publicKeySpkiBase64Url('acme.staging.sandbox')).resolves.toBe(
      toBase64Url(new Uint8Array(91)),
    )
    expect(native.publicKeySpkiBase64Url).toHaveBeenCalledWith('acme.staging', 'sandbox')
  })

  it('delegates acknowledgement to the native module as structured identity', async () => {
    const native = nativeModule()
    requireNative.mockReturnValue(native)

    const bridge = resolveNativeBridge()
    await expect(bridge.acknowledgeRegistration('acme.staging.sandbox')).resolves.toBeUndefined()
    // The alias is split from the right, exactly as resolve and SPKI do, and
    // reaches the acknowledgeRegistration(appId, environment) the Expo module
    // exposes on both platforms.
    expect(native.acknowledgeRegistration).toHaveBeenCalledWith('acme.staging', 'sandbox')
  })

  it('rejects acknowledgement for a malformed alias before calling native', async () => {
    const native = nativeModule({
      resolveOrCreate: jest.fn(),
      publicKeySpkiBase64Url: jest.fn(),
      acknowledgeRegistration: jest.fn(),
    })
    requireNative.mockReturnValue(native)

    const bridge = resolveNativeBridge()
    await expect(bridge.acknowledgeRegistration('acme.mainnet')).rejects.toThrow(
      /unknown environment/,
    )
    expect(native.acknowledgeRegistration).not.toHaveBeenCalled()
  })

  it('surfaces a native acknowledgement rejection to the caller', async () => {
    const native = nativeModule({
      resolveOrCreate: jest.fn(),
      publicKeySpkiBase64Url: jest.fn(),
      acknowledgeRegistration: jest.fn(async () => {
        throw new Error('NOT_INITIALIZED')
      }),
    })
    requireNative.mockReturnValue(native)

    const bridge = resolveNativeBridge()
    // The bridge does not swallow it; NativeSecureKeyStore's guardNative maps it.
    await expect(bridge.acknowledgeRegistration('acme.sandbox')).rejects.toThrow(/NOT_INITIALIZED/)
  })

  it('delegates sign to native signDeviceAuthorization with structured identity', async () => {
    const signature = toBase64Url(new Uint8Array(64))
    const native = nativeModule({
      resolveOrCreate: jest.fn(),
      publicKeySpkiBase64Url: jest.fn(),
      acknowledgeRegistration: jest.fn(),
      signDeviceAuthorization: jest.fn(async () => signature),
    })
    requireNative.mockReturnValue(native)

    const bridge = resolveNativeBridge()
    await expect(bridge.sign('acme.staging.sandbox', 'AAAA')).resolves.toBe(signature)
    // Exactly three arguments: the native SDK sets all of the biometric prompt
    // text from the validated operation, so the bridge passes none.
    expect(native.signDeviceAuthorization).toHaveBeenCalledWith('acme.staging', 'sandbox', 'AAAA')
    expect(native).not.toHaveProperty('sign')
  })

  it('rejects sign for a malformed alias before calling native', async () => {
    const native = nativeModule({
      resolveOrCreate: jest.fn(),
      publicKeySpkiBase64Url: jest.fn(),
      acknowledgeRegistration: jest.fn(),
      signDeviceAuthorization: jest.fn(),
    })
    requireNative.mockReturnValue(native)

    const bridge = resolveNativeBridge()
    await expect(bridge.sign('acme.mainnet', 'AAAA')).rejects.toThrow(/unknown environment/)
    expect(native.signDeviceAuthorization).not.toHaveBeenCalled()
  })

  it('fail-closes sign when native signDeviceAuthorization is absent', async () => {
    const native = nativeModule({
      resolveOrCreate: jest.fn(),
      publicKeySpkiBase64Url: jest.fn(),
      acknowledgeRegistration: jest.fn(),
    })
    requireNative.mockReturnValue(native)

    const bridge = resolveNativeBridge()
    const err = await bridge.sign('acme.sandbox', 'AAAA').catch((e: unknown) => e)
    expect(isDaaError(err) && err.detail.kind === 'contract_violation').toBe(true)
    expect(native).not.toHaveProperty('sign')
    expect(native).not.toHaveProperty('signDeviceAuthorization')
  })

  it('fail-closes when native resolveOrCreate returns an unknown resolution', async () => {
    const native = nativeModule({
      resolveOrCreate: jest.fn(async () => 'rotated'),
      publicKeySpkiBase64Url: jest.fn(),
      acknowledgeRegistration: jest.fn(),
    })
    requireNative.mockReturnValue(native)

    const bridge = resolveNativeBridge()
    await expect(bridge.resolveOrCreate('acme.sandbox')).rejects.toThrow(/unknown resolution/)
  })

  it('delegates registration signing to native signRegistrationDeviceAuthorization, a DIFFERENT native function from sign', async () => {
    const signature = toBase64Url(new Uint8Array(64))
    const native = nativeModule({
      resolveOrCreate: jest.fn(),
      publicKeySpkiBase64Url: jest.fn(),
      acknowledgeRegistration: jest.fn(),
      signDeviceAuthorization: jest.fn(async () => {
        throw new Error('signDeviceAuthorization should not be reached for registration')
      }),
      signRegistrationDeviceAuthorization: jest.fn(async () => signature),
    })
    requireNative.mockReturnValue(native)

    const bridge = resolveNativeBridge()
    await expect(
      bridge.signRegistrationDeviceAuthorization('acme.staging.sandbox', 'AAAA'),
    ).resolves.toBe(signature)
    // No prompt text here either; see the signDeviceAuthorization case above.
    expect(native.signRegistrationDeviceAuthorization).toHaveBeenCalledWith(
      'acme.staging',
      'sandbox',
      'AAAA',
    )
    expect(native.signDeviceAuthorization).not.toHaveBeenCalled()
  })

  it('rejects registration signing for a malformed alias before calling native', async () => {
    const native = nativeModule({
      resolveOrCreate: jest.fn(),
      publicKeySpkiBase64Url: jest.fn(),
      acknowledgeRegistration: jest.fn(),
      signRegistrationDeviceAuthorization: jest.fn(),
    })
    requireNative.mockReturnValue(native)

    const bridge = resolveNativeBridge()
    await expect(
      bridge.signRegistrationDeviceAuthorization('acme.mainnet', 'AAAA'),
    ).rejects.toThrow(/unknown environment/)
    expect(native.signRegistrationDeviceAuthorization).not.toHaveBeenCalled()
  })

  it('fail-closes registration signing when native signRegistrationDeviceAuthorization is absent', async () => {
    const native = nativeModule({
      resolveOrCreate: jest.fn(),
      publicKeySpkiBase64Url: jest.fn(),
      acknowledgeRegistration: jest.fn(),
    })
    requireNative.mockReturnValue(native)

    const bridge = resolveNativeBridge()
    const err = await bridge
      .signRegistrationDeviceAuthorization('acme.sandbox', 'AAAA')
      .catch((e: unknown) => e)
    expect(isDaaError(err) && err.detail.kind === 'contract_violation').toBe(true)
    expect(native).not.toHaveProperty('signRegistrationDeviceAuthorization')
  })
})
