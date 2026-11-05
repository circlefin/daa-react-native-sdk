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

import { getSignedResource, postSignedResource } from '../api/signedResource'
import { DEVICE_AUTHORIZATION_HEADER } from '../auth/deviceAuthorization'
import { fromBase64Url, toBase64Url } from '../crypto/base64url'
import { serializeBody } from '../crypto/serialization'
import { sha256 } from '../crypto/sha256'
import { isDaaError } from '../errors'
import type { DaaSdkError } from '../errors'
import type { OwnerAuthKey } from '../securekey/SecureKey'
import { InMemorySecureKeyStore } from '../testing'
import type { DaaHttpRequest, DaaHttpResponse, DaaTransport } from '../transport/DaaTransport'

const AUTH_KEY_ID = '11111111-1111-4111-8111-111111111111'
const IDEMPOTENCY_KEY = '22222222-2222-4222-a222-222222222222'
const PATH = '/v1/accounts/transfers'

class SequenceTransport implements DaaTransport {
  readonly sent: DaaHttpRequest[] = []

  constructor(private readonly responses: DaaHttpResponse[]) {}

  async send(request: DaaHttpRequest): Promise<DaaHttpResponse> {
    this.sent.push(request)
    const next = this.responses.shift()
    if (next === undefined) {
      throw new Error('transport has no more responses')
    }
    return next
  }
}

function bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text)
}

function envelope(payload: string): Uint8Array {
  return bytes(`{"data":${payload}}`)
}

function errorBody(code: string | number): Uint8Array {
  return bytes(`{"status":{"code":${JSON.stringify(code)}}}`)
}

async function registeredKey(): Promise<OwnerAuthKey> {
  const key = await new InMemorySecureKeyStore().resolveOrCreate({
    appId: 'app-123',
    environment: 'sandbox',
    clientEntityId: '00000000-0000-4000-8000-000000000001',
  })
  await key.acknowledgeRegistration()
  return key
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

async function post(
  transport: DaaTransport,
  bodyBytes: Uint8Array,
  authKey: OwnerAuthKey,
): Promise<string> {
  return postSignedResource({
    transport,
    operation: 'transfer',
    authKey,
    authKeyId: AUTH_KEY_ID,
    bodyBytes,
    expectedStatus: 201,
    decode: (value) => {
      if (typeof value !== 'object' || value === null || !('id' in value)) {
        throw new Error('missing id')
      }
      const id = value.id
      if (typeof id !== 'string') {
        throw new Error('id is not a string')
      }
      return id
    },
  })
}

describe('postSignedResource', () => {
  it('sends the exact body bytes with a compact X-Device-Authorization JWS and query=null', async () => {
    const authKey = await registeredKey()
    const bodyBytes = serializeBody({ idempotencyKey: IDEMPOTENCY_KEY, amount: '1.00' })
    const transport = new SequenceTransport([
      { status: 201, headers: {}, bodyBytes: envelope('{"id":"transfer-1"}') },
    ])

    await expect(post(transport, bodyBytes, authKey)).resolves.toBe('transfer-1')
    expect(transport.sent).toHaveLength(1)
    const request = transport.sent[0]
    expect(request?.method).toBe('POST')
    expect(request?.path).toBe(PATH)
    expect(request?.query).toBeNull()
    expect(request?.bodyBytes).toBe(bodyBytes)
    expect(request?.headers['Content-Type']).toBe('application/json')
    const compact = request?.headers[DEVICE_AUTHORIZATION_HEADER]
    expect(compact).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/)

    if (compact === undefined) {
      throw new Error('missing device authorization')
    }
    const payloadJson = new TextDecoder().decode(fromBase64Url(compact.split('.')[1] ?? ''))
    const payload: unknown = JSON.parse(payloadJson)
    expect(payload).toMatchObject({
      canonical_path: PATH,
      method: 'POST',
      discriminator: 'transfer',
      schema_version: 1,
      idempotency_key: IDEMPOTENCY_KEY,
    })
  })

  it('rejects a GET registry operation', async () => {
    const authKey = await registeredKey()
    const transport = new SequenceTransport([])
    expect(
      await detailOf(
        postSignedResource({
          transport,
          operation: 'get_device_context',
          authKey,
          authKeyId: AUTH_KEY_ID,
          bodyBytes: serializeBody({}),
          expectedStatus: 200,
          decode: (value) => value,
        }),
      ),
    ).toEqual({ kind: 'contract_violation' })
    expect(transport.sent).toHaveLength(0)
  })

  it('does not retry DEVICE_AUTHORIZATION_REPLAYED (420043) and maps it to contract_violation', async () => {
    const authKey = await registeredKey()
    const bodyBytes = serializeBody({ idempotencyKey: IDEMPOTENCY_KEY })
    const transport = new SequenceTransport([
      {
        status: 401,
        headers: { 'X-Request-Id': 'req-replayed' },
        bodyBytes: errorBody(420043),
      },
    ])

    expect(await detailOf(post(transport, bodyBytes, authKey))).toEqual({
      kind: 'contract_violation',
      correlationId: 'req-replayed',
    })
    expect(transport.sent).toHaveLength(1)
  })

  it('maps DEVICE_AUTHORIZATION_REQUEST_MISMATCH (420036) to contract_violation without retrying', async () => {
    const authKey = await registeredKey()
    const bodyBytes = serializeBody({ idempotencyKey: IDEMPOTENCY_KEY })
    const transport = new SequenceTransport([
      {
        status: 403,
        headers: { 'X-Request-Id': 'req-mismatch' },
        bodyBytes: errorBody(420036),
      },
    ])

    expect(await detailOf(post(transport, bodyBytes, authKey))).toEqual({
      kind: 'contract_violation',
      correlationId: 'req-mismatch',
    })
    expect(transport.sent).toHaveLength(1)
  })

  it('maps DEVICE_AUTHORIZATION_INVALID (420031) to contract_violation without a JWS in the message', async () => {
    const authKey = await registeredKey()
    const bodyBytes = serializeBody({ idempotencyKey: IDEMPOTENCY_KEY })
    const transport = new SequenceTransport([
      {
        status: 400,
        headers: { 'X-Request-Id': 'req-invalid' },
        bodyBytes: errorBody(420031),
      },
    ])

    const err = await post(transport, bodyBytes, authKey).catch((e: unknown) => e)
    expect(isDaaError(err)).toBe(true)
    if (!isDaaError(err)) return
    expect(err.detail).toEqual({ kind: 'contract_violation', correlationId: 'req-invalid' })
    expect(err.message).not.toMatch(/[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/)
    expect(err.message).not.toMatch(/eyJ/)
    expect(transport.sent).toHaveLength(1)
  })

  // A non-numeric string code classifies as `api`, even when it spells a known
  // error name. Sent once: there is no fresh-JWS
  // retry, because DAA has no expiry code that could trigger one.
  it.each(['DEVICE_AUTHORIZATION_INVALID', 'DEVICE_AUTHORIZATION_EXPIRED'])(
    'classifies the name string %s as api and sends once',
    async (name) => {
      const authKey = await registeredKey()
      const bodyBytes = serializeBody({ idempotencyKey: IDEMPOTENCY_KEY })
      const transport = new SequenceTransport([
        { status: 401, headers: {}, bodyBytes: errorBody(name) },
        { status: 201, headers: {}, bodyBytes: envelope('{"id":"transfer-2"}') },
      ])

      expect(await detailOf(post(transport, bodyBytes, authKey))).toEqual({
        kind: 'api',
        httpStatus: 401,
        daaStatusCode: name,
        retryable: false,
      })
      expect(transport.sent).toHaveLength(1)
    },
  )

  it('maps a 409 IDEMPOTENCY_KEY_REUSED (420034) to idempotency_conflict with the signed request’s own key', async () => {
    const authKey = await registeredKey()
    const bodyBytes = serializeBody({ idempotencyKey: IDEMPOTENCY_KEY, amount: '1.00' })
    const transport = new SequenceTransport([
      {
        status: 409,
        headers: { 'X-Request-Id': 'req-conflict' },
        bodyBytes: errorBody(420034),
      },
    ])

    expect(await detailOf(post(transport, bodyBytes, authKey))).toEqual({
      kind: 'idempotency_conflict',
      idempotencyKey: IDEMPOTENCY_KEY,
      correlationId: 'req-conflict',
    })
    expect(transport.sent).toHaveLength(1)
  })

  it('keeps a 409 with the name string IDEMPOTENCY_KEY_REUSED an api failure and sends once', async () => {
    const authKey = await registeredKey()
    const bodyBytes = serializeBody({ idempotencyKey: IDEMPOTENCY_KEY, amount: '1.00' })
    const transport = new SequenceTransport([
      {
        status: 409,
        headers: { 'X-Request-Id': 'req-conflict-name' },
        bodyBytes: errorBody('IDEMPOTENCY_KEY_REUSED'),
      },
      { status: 201, headers: {}, bodyBytes: envelope('{"id":"transfer-2"}') },
    ])

    expect(await detailOf(post(transport, bodyBytes, authKey))).toEqual({
      kind: 'api',
      httpStatus: 409,
      daaStatusCode: 'IDEMPOTENCY_KEY_REUSED',
      retryable: false,
    })
    expect(transport.sent).toHaveLength(1)
  })

  it('does not map a 409 for a different reason to idempotency_conflict even with a recoverable idempotency key', async () => {
    const authKey = await registeredKey()
    const bodyBytes = serializeBody({ idempotencyKey: IDEMPOTENCY_KEY, amount: '1.00' })
    const transport = new SequenceTransport([
      {
        status: 409,
        headers: { 'X-Request-Id': 'req-conflict-other' },
        // A 409 whose body carries some other status code entirely — not the
        // one that means "safe to retry with the same key and bytes". A body
        // that merely has the right HTTP status must not be trusted into
        // `idempotency_conflict` on that basis alone.
        bodyBytes: errorBody('SOME_OTHER_CONFLICT'),
      },
    ])

    const detail = await detailOf(post(transport, bodyBytes, authKey))
    expect(detail.kind).not.toBe('idempotency_conflict')
    expect(detail).toEqual({
      kind: 'api',
      httpStatus: 409,
      daaStatusCode: 'SOME_OTHER_CONFLICT',
      retryable: false,
    })
    expect(transport.sent).toHaveLength(1)
  })
})

const CONTEXT_PATH = '/v1/accounts/auth/context'

async function get(transport: DaaTransport, authKey: OwnerAuthKey): Promise<string> {
  return getSignedResource({
    transport,
    operation: 'get_device_context',
    authKey,
    authKeyId: AUTH_KEY_ID,
    expectedStatus: 200,
    decode: (value) => {
      if (typeof value !== 'object' || value === null || !('authKeyId' in value)) {
        throw new Error('missing authKeyId')
      }
      const authKeyId = value.authKeyId
      if (typeof authKeyId !== 'string') {
        throw new Error('authKeyId is not a string')
      }
      return authKeyId
    },
  })
}

describe('getSignedResource', () => {
  it('sends a bodyless GET with a compact X-Device-Authorization JWS and query=null', async () => {
    const authKey = await registeredKey()
    const transport = new SequenceTransport([
      { status: 200, headers: {}, bodyBytes: envelope(`{"authKeyId":"${AUTH_KEY_ID}"}`) },
    ])

    await expect(get(transport, authKey)).resolves.toBe(AUTH_KEY_ID)
    expect(transport.sent).toHaveLength(1)
    const request = transport.sent[0]
    expect(request?.method).toBe('GET')
    expect(request?.path).toBe(CONTEXT_PATH)
    expect(request?.query).toBeNull()
    // No body to describe, so no Content-Type — the same bodyless shape
    // `resourceRequest.ts`'s unsigned `readResource` sends.
    expect(request?.bodyBytes).toBeNull()
    // No Content-Type either: the only header a bodyless signed GET carries is
    // the authorization JWS.
    expect(Object.keys(request?.headers ?? {})).toEqual([DEVICE_AUTHORIZATION_HEADER])
    const compact = request?.headers[DEVICE_AUTHORIZATION_HEADER]
    expect(compact).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/)

    if (compact === undefined) {
      throw new Error('missing device authorization')
    }
    const payloadJson = new TextDecoder().decode(fromBase64Url(compact.split('.')[1] ?? ''))
    const payload: unknown = JSON.parse(payloadJson)
    expect(payload).toMatchObject({
      canonical_path: CONTEXT_PATH,
      method: 'GET',
      discriminator: 'get_device_context',
      schema_version: 1,
      aud: 'circle-digital-asset-accounts',
    })
    // The bodyless rule: hash the empty byte array and omit idempotency_key.
    expect(payload).not.toHaveProperty('idempotency_key')
    expect((payload as { body_sha256: string }).body_sha256).toBe(
      toBase64Url(sha256(new Uint8Array(0))),
    )
  })

  it('rejects a POST registry operation', async () => {
    const authKey = await registeredKey()
    const transport = new SequenceTransport([])
    expect(
      await detailOf(
        getSignedResource({
          transport,
          operation: 'transfer',
          authKey,
          authKeyId: AUTH_KEY_ID,
          expectedStatus: 201,
          decode: (value) => value,
        }),
      ),
    ).toEqual({ kind: 'contract_violation' })
    expect(transport.sent).toHaveLength(0)
  })

  it.each(['DEVICE_AUTHORIZATION_INVALID', 'DEVICE_AUTHORIZATION_EXPIRED'])(
    'classifies the name string %s as api and sends once',
    async (name) => {
      const authKey = await registeredKey()
      const transport = new SequenceTransport([
        { status: 403, headers: {}, bodyBytes: errorBody(name) },
        { status: 200, headers: {}, bodyBytes: envelope(`{"authKeyId":"${AUTH_KEY_ID}"}`) },
      ])

      expect(await detailOf(get(transport, authKey))).toEqual({
        kind: 'api',
        httpStatus: 403,
        daaStatusCode: name,
        retryable: false,
      })
      expect(transport.sent).toHaveLength(1)
    },
  )

  it('maps DEVICE_AUTHORIZATION_REPLAYED (420043) to contract_violation without retrying', async () => {
    const authKey = await registeredKey()
    const transport = new SequenceTransport([
      {
        status: 401,
        headers: { 'X-Request-Id': 'req-replayed' },
        bodyBytes: errorBody(420043),
      },
    ])

    expect(await detailOf(get(transport, authKey))).toEqual({
      kind: 'contract_violation',
      correlationId: 'req-replayed',
    })
    expect(transport.sent).toHaveLength(1)
  })

  it('accepts only the documented 200', async () => {
    const authKey = await registeredKey()
    for (const status of [201, 204, 299]) {
      const transport = new SequenceTransport([
        { status, headers: {}, bodyBytes: envelope(`{"authKeyId":"${AUTH_KEY_ID}"}`) },
      ])
      const detail = await detailOf(get(transport, authKey))
      expect(detail).toEqual({ kind: 'api', httpStatus: status, retryable: false })
    }
  })

  it('has no idempotency key to recover from a bodyless GET, so a 409 stays an api failure', async () => {
    const authKey = await registeredKey()
    const transport = new SequenceTransport([
      {
        status: 409,
        headers: { 'X-Request-Id': 'req-409' },
        bodyBytes: errorBody(420034),
      },
    ])

    expect(await detailOf(get(transport, authKey))).toEqual({
      kind: 'api',
      httpStatus: 409,
      daaStatusCode: 420034,
      retryable: false,
    })
  })
})
