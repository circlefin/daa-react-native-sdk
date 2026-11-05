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

import {
  authorizeRegistrationComplete,
  type RegistrationAuthorizationClock,
  type RegistrationCompleteAuthorizationRequest,
} from '../auth/registrationAuthorization'
import { webCryptoRegistrationFlowKeyProvider } from '../auth/RegistrationFlowKey'
import type { RegistrationFlowKey } from '../auth/RegistrationFlowKey'
import { fromBase64Url } from '../crypto/base64url'
import { serializeBody } from '../crypto/serialization'
import { isDaaError } from '../errors'
import type { DaaSdkError } from '../errors'
import type { OwnerAuthKey } from '../securekey/SecureKey'
import { InMemorySecureKeyStore } from '../testing'

const CLIENT_ENTITY_ID = '00000000-0000-4000-8000-000000000001'
const IDEMPOTENCY_KEY = '22222222-2222-4222-a222-222222222222'
const FLOW_JTI = '33333333-3333-4333-8333-333333333333'
const DEVICE_JTI = '44444444-4444-4444-8444-444444444444'
const NOW = 1_785_990_000

const REQUEST_CLAIMS = [
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
const BINDING_CLAIMS = [
  'auth_key_thumbprint',
  'code_verifier_sha256',
  'profile_id',
  'registration_handle_sha256',
]

function makeClock(): RegistrationAuthorizationClock {
  let calls = 0
  return {
    nowEpochSeconds: () => NOW,
    jti: () => {
      calls += 1
      return calls === 1 ? FLOW_JTI : DEVICE_JTI
    },
  }
}

async function registeredAuthKey(): Promise<OwnerAuthKey> {
  const key = await new InMemorySecureKeyStore().resolveOrCreate({
    appId: 'app-123',
    environment: 'sandbox',
    clientEntityId: CLIENT_ENTITY_ID,
  })
  await key.acknowledgeRegistration()
  return key
}

async function flowKey(): Promise<RegistrationFlowKey> {
  return webCryptoRegistrationFlowKeyProvider().generate()
}

function baseRequest(overrides: Partial<RegistrationCompleteAuthorizationRequest> = {}): Omit<
  RegistrationCompleteAuthorizationRequest,
  'flowKey' | 'authKey'
> & {
  flowKey?: RegistrationFlowKey
  authKey?: OwnerAuthKey
} {
  return {
    bodyBytes: serializeBody({
      idempotencyKey: IDEMPOTENCY_KEY,
      registrationHandle: 'h'.repeat(32),
      registrationCodeVerifier: 'v'.repeat(43),
      authKeyPublicKey: 'I'.repeat(122),
    }),
    registrationHandle: 'h'.repeat(32),
    registrationCodeVerifier: 'v'.repeat(43),
    clientEntityId: CLIENT_ENTITY_ID,
    ...overrides,
  }
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

describe('authorizeRegistrationComplete', () => {
  it('rejects a non-UUID clientEntityId', async () => {
    const request = {
      ...baseRequest({ clientEntityId: 'not-a-uuid' }),
      flowKey: await flowKey(),
      authKey: await registeredAuthKey(),
    }
    expect(await detailOf(authorizeRegistrationComplete(request, makeClock()))).toEqual({
      kind: 'contract_violation',
    })
  })

  it('rejects a signed body missing idempotencyKey', async () => {
    const request = {
      ...baseRequest({
        bodyBytes: serializeBody({
          registrationHandle: 'h'.repeat(32),
          registrationCodeVerifier: 'v'.repeat(43),
          authKeyPublicKey: 'I'.repeat(122),
        }),
      }),
      flowKey: await flowKey(),
      authKey: await registeredAuthKey(),
    }
    expect(await detailOf(authorizeRegistrationComplete(request, makeClock()))).toEqual({
      kind: 'contract_violation',
    })
  })

  it('rejects a device signature that is not 64 bytes', async () => {
    const authKey: OwnerAuthKey = {
      publicKeySpkiBase64Url: async () => (await registeredAuthKey()).publicKeySpkiBase64Url(),
      thumbprint: async () => 'x',
      resolution: () => 'existing',
      acknowledgeRegistration: async () => undefined,
      signExactBytes: async () => {
        throw new Error('signExactBytes should not be reached for the registration device proof')
      },
      signRegistrationDeviceAuthorization: async () => new Uint8Array(63),
    }
    const request = { ...baseRequest(), flowKey: await flowKey(), authKey }
    expect(await detailOf(authorizeRegistrationComplete(request, makeClock()))).toEqual({
      kind: 'contract_violation',
    })
  })

  it('signs the registration device proof through signRegistrationDeviceAuthorization, never signExactBytes', async () => {
    let registrationCalls = 0
    let exactBytesCalls = 0
    const real = await registeredAuthKey()
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
        // Reuse the same underlying key material so the produced JWS is still
        // a valid 64-byte signature; only the routing is under test here.
        return real.signExactBytes(message)
      },
    }
    const request = { ...baseRequest(), flowKey: await flowKey(), authKey }
    await authorizeRegistrationComplete(request, makeClock())

    expect(registrationCalls).toBe(1)
    expect(exactBytesCalls).toBe(0)
  })

  it('rejects a flow signature that is not 64 bytes', async () => {
    const badFlowKey: RegistrationFlowKey = {
      publicKeySpkiBase64Url: async () => (await flowKey()).publicKeySpkiBase64Url(),
      signExactBytes: async () => new Uint8Array(63),
      release: async () => undefined,
    }
    const request = { ...baseRequest(), flowKey: badFlowKey, authKey: await registeredAuthKey() }
    expect(await detailOf(authorizeRegistrationComplete(request, makeClock()))).toEqual({
      kind: 'contract_violation',
    })
  })

  it('signs the device and flow JWS with their own typ, sharing the request claims bar jti', async () => {
    const request = {
      ...baseRequest(),
      flowKey: await flowKey(),
      authKey: await registeredAuthKey(),
    }
    const { deviceJws, flowJws } = await authorizeRegistrationComplete(request, makeClock())

    const deviceHeader = jsonOf(splitCompact(deviceJws).header)
    const flowHeader = jsonOf(splitCompact(flowJws).header)
    expect(deviceHeader).toMatchObject({ alg: 'ES256', typ: 'daa-device-authorization+jws' })
    expect(flowHeader).toMatchObject({
      alg: 'ES256',
      typ: 'daa-registration-flow-authorization+jws',
    })

    const devicePayload = jsonOf(splitCompact(deviceJws).payload) as Record<string, unknown>
    const flowPayload = jsonOf(splitCompact(flowJws).payload) as Record<string, unknown>
    expect(devicePayload).toMatchObject({
      discriminator: 'device_key_registration.v1',
      schema_version: 1,
      jti: DEVICE_JTI,
    })
    expect(flowPayload).toMatchObject({
      discriminator: 'device_key_registration.v1',
      schema_version: 1,
      profile_id: CLIENT_ENTITY_ID,
      jti: FLOW_JTI,
    })
    // The request claims carry the same values in both proofs, bar jti.
    for (const claim of REQUEST_CLAIMS.filter((name) => name !== 'jti')) {
      expect(devicePayload[claim]).toEqual(flowPayload[claim])
    }
    expect(devicePayload.jti).not.toBe(flowPayload.jti)
  })

  it('sends exactly the 10 request claims in the device proof and none of the binding claims', async () => {
    const request = {
      ...baseRequest(),
      flowKey: await flowKey(),
      authKey: await registeredAuthKey(),
    }
    const { deviceJws } = await authorizeRegistrationComplete(request, makeClock())

    const devicePayload = jsonOf(splitCompact(deviceJws).payload) as Record<string, unknown>
    expect(Object.keys(devicePayload).sort()).toEqual(REQUEST_CLAIMS)
    for (const claim of BINDING_CLAIMS) {
      expect(devicePayload).not.toHaveProperty(claim)
    }
  })

  it('sends all 14 claims in the flow proof: the request claims plus the binding claims', async () => {
    const request = {
      ...baseRequest(),
      flowKey: await flowKey(),
      authKey: await registeredAuthKey(),
    }
    const { flowJws } = await authorizeRegistrationComplete(request, makeClock())

    const flowPayload = jsonOf(splitCompact(flowJws).payload) as Record<string, unknown>
    expect(Object.keys(flowPayload).sort()).toEqual([...REQUEST_CLAIMS, ...BINDING_CLAIMS].sort())
  })
})
