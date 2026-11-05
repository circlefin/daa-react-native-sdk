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

import { authorizeExactRequest, deviceAuthorizationProfile } from '../auth/deviceAuthorization'
import type {
  DeviceAuthorizationClock,
  DeviceAuthorizationOperation,
} from '../auth/deviceAuthorization'
import { fromBase64Url, toBase64Url } from '../crypto/base64url'
import { toArrayBuffer } from '../crypto/bytes'
import { serializeBody, serializeEmptyBody } from '../crypto/serialization'
import { sha256 } from '../crypto/sha256'
import { isDaaError } from '../errors'
import type { DaaSdkError } from '../errors'
import type { OwnerAuthKey } from '../securekey/SecureKey'
import { InMemorySecureKeyStore } from '../testing'

const AUTH_KEY_ID = '11111111-1111-4111-8111-111111111111'
const IDEMPOTENCY_KEY = '22222222-2222-4222-a222-222222222222'
const JTI = '33333333-3333-4333-8333-333333333333'
const NOW = 1_785_990_000
const EMPTY_BODY_SHA256 = '47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU'

const PAYLOAD_WITH_IDEMPOTENCY = [
  'aud',
  'body_sha256',
  'canonical_path',
  'discriminator',
  'exp',
  'iat',
  'idempotency_key',
  'jti',
  'method',
  'schema_version',
]

const PAYLOAD_WITHOUT_IDEMPOTENCY = PAYLOAD_WITH_IDEMPOTENCY.filter(
  (key) => key !== 'idempotency_key',
)

const clock: DeviceAuthorizationClock = {
  nowEpochSeconds: () => NOW,
  jti: () => JTI,
}

const REGISTRY: ReadonlyArray<{
  operation: DeviceAuthorizationOperation
  method: 'GET' | 'POST'
  canonicalPath: string
}> = [
  { operation: 'create_account', method: 'POST', canonicalPath: '/v1/accounts' },
  { operation: 'transfer', method: 'POST', canonicalPath: '/v1/accounts/transfers' },
  { operation: 'withdrawal', method: 'POST', canonicalPath: '/v1/accounts/withdrawals' },
  {
    operation: 'complete_social_login',
    method: 'POST',
    canonicalPath: '/v1/accounts/auth/sessions',
  },
  { operation: 'get_device_context', method: 'GET', canonicalPath: '/v1/accounts/auth/context' },
  {
    operation: 'register_device_key',
    method: 'POST',
    canonicalPath: '/v1/accounts/auth/deviceKeyRegistration',
  },
]

async function registeredKey(): Promise<OwnerAuthKey> {
  const key = await new InMemorySecureKeyStore().resolveOrCreate({
    appId: 'app-123',
    environment: 'sandbox',
    clientEntityId: '00000000-0000-4000-8000-000000000001',
  })
  await key.acknowledgeRegistration()
  return key
}

async function compactJws(
  authKey: OwnerAuthKey,
  args: {
    operation?: DeviceAuthorizationOperation
    bodyBytes?: Uint8Array
    authKeyId?: string
    clock?: DeviceAuthorizationClock
  } = {},
): Promise<string> {
  const bodyBytes =
    args.bodyBytes ?? serializeBody({ idempotencyKey: IDEMPOTENCY_KEY, amount: '1.00' })
  return authorizeExactRequest(
    {
      authKey,
      authKeyId: args.authKeyId ?? AUTH_KEY_ID,
      operation: args.operation ?? 'transfer',
      bodyBytes,
    },
    args.clock ?? clock,
  )
}

function splitCompact(compact: string): { header: string; payload: string; signature: string } {
  const parts = compact.split('.')
  if (
    parts.length !== 3 ||
    parts[0] === undefined ||
    parts[1] === undefined ||
    parts[2] === undefined
  ) {
    throw new Error('expected compact JWS')
  }
  return { header: parts[0], payload: parts[1], signature: parts[2] }
}

function jsonOf(segment: string): unknown {
  return JSON.parse(new TextDecoder().decode(fromBase64Url(segment)))
}

function claimKeys(claims: unknown): string[] {
  if (typeof claims !== 'object' || claims === null) {
    throw new Error('expected claims object')
  }
  return Object.keys(claims).sort()
}

async function detailOf(operation: Promise<unknown>): Promise<DaaSdkError> {
  try {
    await operation
  } catch (err) {
    if (isDaaError(err)) {
      return err.detail
    }
    throw err
  }
  throw new Error('expected the operation to fail')
}

describe('authorizeExactRequest', () => {
  it('binds body_sha256 to the exact serialized bytes that will be sent', async () => {
    const authKey = await registeredKey()
    const bodyBytes = serializeBody({ idempotencyKey: IDEMPOTENCY_KEY, amount: '1.00' })
    const compact = await compactJws(authKey, { bodyBytes })
    const claims = jsonOf(splitCompact(compact).payload)

    expect(claims).toEqual({
      body_sha256: toBase64Url(sha256(bodyBytes)),
      idempotency_key: IDEMPOTENCY_KEY,
      canonical_path: '/v1/accounts/transfers',
      method: 'POST',
      aud: 'circle-digital-asset-accounts',
      discriminator: 'transfer',
      schema_version: 1,
      jti: JTI,
      iat: NOW,
      exp: NOW + 300,
    })
    expect(claimKeys(claims)).toEqual(PAYLOAD_WITH_IDEMPOTENCY)
  })

  it('uses the published JWS header profile and the DeviceContext authKeyId as kid', async () => {
    const compact = await compactJws(await registeredKey())
    expect(jsonOf(splitCompact(compact).header)).toEqual({
      alg: 'ES256',
      kid: AUTH_KEY_ID,
      typ: 'aw-device-authorization+jws',
    })
  })

  it('hashes the empty byte array and omits idempotency_key for a bodyless request', async () => {
    const compact = await compactJws(await registeredKey(), {
      operation: 'get_device_context',
      bodyBytes: serializeEmptyBody(),
    })
    const claims = jsonOf(splitCompact(compact).payload)
    expect(claims).toEqual({
      body_sha256: EMPTY_BODY_SHA256,
      canonical_path: '/v1/accounts/auth/context',
      method: 'GET',
      aud: 'circle-digital-asset-accounts',
      discriminator: 'get_device_context',
      schema_version: 1,
      jti: JTI,
      iat: NOW,
      exp: NOW + 300,
    })
    expect(claimKeys(claims)).toEqual(PAYLOAD_WITHOUT_IDEMPOTENCY)
  })

  it('omits idempotency_key when the JSON body has none', async () => {
    const compact = await compactJws(await registeredKey(), {
      bodyBytes: serializeBody({ amount: '1.00' }),
    })
    const claims = jsonOf(splitCompact(compact).payload)
    expect(claims).not.toHaveProperty('idempotency_key')
    expect(claimKeys(claims)).toEqual(PAYLOAD_WITHOUT_IDEMPOTENCY)
  })

  it('does not read idempotencyKey from Object.prototype', async () => {
    const previous = Object.getOwnPropertyDescriptor(Object.prototype, 'idempotencyKey')
    Object.defineProperty(Object.prototype, 'idempotencyKey', {
      configurable: true,
      value: IDEMPOTENCY_KEY,
    })

    try {
      const compact = await compactJws(await registeredKey(), {
        bodyBytes: serializeBody({ amount: '1.00' }),
      })
      const claims = jsonOf(splitCompact(compact).payload)
      expect(claims).not.toHaveProperty('idempotency_key')
    } finally {
      if (previous === undefined) {
        Reflect.deleteProperty(Object.prototype, 'idempotencyKey')
      } else {
        Object.defineProperty(Object.prototype, 'idempotencyKey', previous)
      }
    }
  })

  it('pins schema_version as the JSON integer 1, not the string v1', async () => {
    const claims = jsonOf(splitCompact(await compactJws(await registeredKey())).payload)
    expect(claims).toMatchObject({ schema_version: 1 })
    if (typeof claims !== 'object' || claims === null || !('schema_version' in claims)) {
      throw new Error('expected schema_version')
    }
    expect(typeof claims.schema_version).toBe('number')
  })

  it('produces a different digest when JSON whitespace changes', async () => {
    const authKey = await registeredKey()
    const compactBody = serializeBody({ a: 1 })
    const spacedBody = new TextEncoder().encode('{"a": 1}')
    const compactDigest = jsonOf(
      splitCompact(await compactJws(authKey, { bodyBytes: compactBody })).payload,
    )
    const spacedDigest = jsonOf(
      splitCompact(await compactJws(authKey, { bodyBytes: spacedBody })).payload,
    )
    expect(compactDigest).toMatchObject({ body_sha256: toBase64Url(sha256(compactBody)) })
    expect(spacedDigest).toMatchObject({ body_sha256: toBase64Url(sha256(spacedBody)) })
    expect(toBase64Url(sha256(compactBody))).not.toBe(toBase64Url(sha256(spacedBody)))
  })

  it('binds each closed registry operation to its method, path, and discriminator', async () => {
    const authKey = await registeredKey()
    for (const entry of REGISTRY) {
      expect(deviceAuthorizationProfile(entry.operation)).toEqual({
        discriminator: entry.operation,
        schemaVersion: 1,
        method: entry.method,
        canonicalPath: entry.canonicalPath,
      })
      const bodyBytes =
        entry.method === 'GET'
          ? serializeEmptyBody()
          : serializeBody({ idempotencyKey: IDEMPOTENCY_KEY })
      const claims = jsonOf(
        splitCompact(await compactJws(authKey, { operation: entry.operation, bodyBytes })).payload,
      )
      expect(claims).toMatchObject({
        discriminator: entry.operation,
        schema_version: 1,
        method: entry.method,
        canonical_path: entry.canonicalPath,
      })
    }
  })

  it('keeps exp - iat at the 300s verifier maximum', async () => {
    const claims = jsonOf(splitCompact(await compactJws(await registeredKey())).payload)
    expect(claims).toMatchObject({ iat: NOW, exp: NOW + 300 })
  })

  it('verifies as compact ES256 over the exact signing input', async () => {
    const authKey = await registeredKey()
    const compact = await compactJws(authKey)
    const { header, payload, signature } = splitCompact(compact)
    const signingInput = new TextEncoder().encode(`${header}.${payload}`)
    const sig = fromBase64Url(signature)
    expect(sig.length).toBe(64)

    const spki = fromBase64Url(await authKey.publicKeySpkiBase64Url())
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
      toArrayBuffer(signingInput),
    )
    expect(ok).toBe(true)
  })

  it('rejects an unregistered AuthKey for post-activation operations', async () => {
    const key = await new InMemorySecureKeyStore().resolveOrCreate({
      appId: 'app-123',
      environment: 'sandbox',
      clientEntityId: '00000000-0000-4000-8000-000000000001',
    })
    expect(await detailOf(compactJws(key))).toEqual({ kind: 'contract_violation' })
  })

  it('allows register_device_key while the AuthKey is still created', async () => {
    const key = await new InMemorySecureKeyStore().resolveOrCreate({
      appId: 'app-123',
      environment: 'sandbox',
      clientEntityId: '00000000-0000-4000-8000-000000000001',
    })
    const compact = await compactJws(key, {
      operation: 'register_device_key',
      bodyBytes: serializeBody({
        idempotencyKey: IDEMPOTENCY_KEY,
        registrationHandle: 'h'.repeat(32),
        authKeyPublicKey: 'I'.repeat(122),
      }),
    })
    expect(jsonOf(splitCompact(compact).header)).toMatchObject({
      typ: 'aw-device-authorization+jws',
      kid: AUTH_KEY_ID,
    })
    expect(jsonOf(splitCompact(compact).payload)).toMatchObject({
      discriminator: 'register_device_key',
    })
  })

  it('signs post-activation operations through signExactBytes, never signRegistrationDeviceAuthorization', async () => {
    let exactBytesCalls = 0
    let registrationCalls = 0
    const real = await registeredKey()
    const authKey: OwnerAuthKey = {
      publicKeySpkiBase64Url: () => real.publicKeySpkiBase64Url(),
      thumbprint: () => real.thumbprint(),
      resolution: () => real.resolution(),
      acknowledgeRegistration: () => real.acknowledgeRegistration(),
      signExactBytes: async (message) => {
        exactBytesCalls += 1
        return real.signExactBytes(message)
      },
      signRegistrationDeviceAuthorization: async (message) => {
        registrationCalls += 1
        return real.signExactBytes(message)
      },
    }
    await compactJws(authKey)

    expect(exactBytesCalls).toBe(1)
    expect(registrationCalls).toBe(0)
  })

  it('rejects a non-UUID authKeyId', async () => {
    expect(await detailOf(compactJws(await registeredKey(), { authKeyId: 'not-a-uuid' }))).toEqual({
      kind: 'contract_violation',
    })
  })

  it('rejects a body whose idempotencyKey is not a UUID', async () => {
    expect(
      await detailOf(
        compactJws(await registeredKey(), { bodyBytes: serializeBody({ idempotencyKey: 'k' }) }),
      ),
    ).toEqual({ kind: 'contract_violation' })
  })

  it('does not put a compact JWS in error messages', async () => {
    const authKey: OwnerAuthKey = {
      publicKeySpkiBase64Url: async () => 'x',
      thumbprint: async () => 'x',
      resolution: () => 'existing',
      acknowledgeRegistration: async () => undefined,
      signExactBytes: async () => new Uint8Array(63),
      signRegistrationDeviceAuthorization: async () => {
        throw new Error('not exercised by post-activation deviceAuthorization tests')
      },
    }
    try {
      await compactJws(authKey)
      throw new Error('expected failure')
    } catch (err) {
      expect(isDaaError(err)).toBe(true)
      if (!isDaaError(err)) return
      expect(err.message).not.toMatch(/[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/)
      expect(err.message).not.toMatch(/eyJ/)
    }
  })
})
