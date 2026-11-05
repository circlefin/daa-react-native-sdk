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

import { createDaaUserClient } from '../api/DaaUserClient'
import { DEVICE_AUTHORIZATION_HEADER } from '../auth/deviceAuthorization'
import { fromBase64Url, toBase64Url } from '../crypto/base64url'
import { sha256 } from '../crypto/sha256'
import { isDaaError } from '../errors'
import type { DaaSdkError } from '../errors'
import type { CreateAccountRequest } from '../models/CreateAccountRequest'
import type { DaaHttpRequest, DaaHttpResponse, DaaTransport } from '../transport/DaaTransport'
import { registeredAuthKey, signingFor, unregisteredAuthKey } from './userClientSigning'

/**
 * The signed account create, end to end through the client.
 *
 * Every wire fact here is written as a literal — the path, the operation
 * discriminator, the schema version, and the exact serialized body — rather
 * than compared against the constant the production code reads. Comparing code
 * to its own constant passes whatever the constant says: a wrong canonical
 * path would pass, because the assertion would move with the defect.
 */

class RecordingTransport implements DaaTransport {
  readonly sent: DaaHttpRequest[] = []

  constructor(private readonly response: DaaHttpResponse) {}

  async send(request: DaaHttpRequest): Promise<DaaHttpResponse> {
    this.sent.push(request)
    return this.response
  }
}

const IDEMPOTENCY_KEY = '22222222-2222-4222-a222-222222222222'
const CLIENT_ENTITY_ID = '33333333-3333-4333-b333-333333333333'
const AUTH_KEY_ID = '11111111-1111-4111-8111-111111111111'

/** A complete account: every field the service guarantees, plus the custody type. */
const CREATED_ACCOUNT =
  '{"accountId":"acct-1","balances":[],"entityId":"e","purpose":"custody",' +
  '"status":"pending","type":"first_party","custodyType":"self"}'

const VALID_REQUEST: CreateAccountRequest = {
  idempotencyKey: IDEMPOTENCY_KEY,
  clientEntityId: CLIENT_ENTITY_ID,
  custodyType: 'self',
  type: 'third_party',
  purpose: 'custody',
  description: 'Primary',
  blockchain: 'ARC',
}

function bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text)
}

function envelope(payload: string): Uint8Array {
  return bytes(`{"data":${payload}}`)
}

async function createdClient(payload = CREATED_ACCOUNT) {
  const transport = new RecordingTransport({
    status: 201,
    headers: { 'X-Request-Id': 'req-create', Location: '/v1/accounts/acct-1' },
    bodyBytes: envelope(payload),
  })
  const signing = signingFor(await registeredAuthKey(), AUTH_KEY_ID)
  return { accounts: createDaaUserClient(transport, 'production', signing).accounts, transport }
}

function claimsOf(request: DaaHttpRequest): Record<string, unknown> {
  const compact = request.headers[DEVICE_AUTHORIZATION_HEADER]
  if (compact === undefined) {
    throw new Error('missing device authorization')
  }
  return JSON.parse(new TextDecoder().decode(fromBase64Url(compact.split('.')[1] ?? '')))
}

function headerOf(request: DaaHttpRequest): Record<string, unknown> {
  const compact = request.headers[DEVICE_AUTHORIZATION_HEADER]
  if (compact === undefined) {
    throw new Error('missing device authorization')
  }
  return JSON.parse(new TextDecoder().decode(fromBase64Url(compact.split('.')[0] ?? '')))
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

describe('the signed request', () => {
  it('posts the registry canonical path with the create_account discriminator', async () => {
    const { accounts, transport } = await createdClient()

    await accounts.create(VALID_REQUEST)

    expect(transport.sent).toHaveLength(1)
    const request = transport.sent[0]
    if (request === undefined) throw new Error('no request was sent')
    expect(request.method).toBe('POST')
    expect(request.path).toBe('/v1/accounts')
    expect(request.query).toBeNull()
    expect(request.headers['Content-Type']).toBe('application/json')
    expect(claimsOf(request)).toMatchObject({
      canonical_path: '/v1/accounts',
      method: 'POST',
      discriminator: 'create_account',
      schema_version: 1,
      aud: 'circle-digital-asset-accounts',
      idempotency_key: IDEMPOTENCY_KEY,
    })
    expect(headerOf(request)).toMatchObject({
      alg: 'ES256',
      kid: AUTH_KEY_ID,
      typ: 'aw-device-authorization+jws',
    })
  })

  it('sends exactly the registry properties, in the registry order', async () => {
    const { accounts, transport } = await createdClient()

    await accounts.create(VALID_REQUEST)

    const sent = transport.sent[0]?.bodyBytes
    if (sent == null) throw new Error('no body was sent')
    expect(new TextDecoder().decode(sent)).toBe(
      `{"idempotencyKey":"${IDEMPOTENCY_KEY}","clientEntityId":"${CLIENT_ENTITY_ID}",` +
        '"custodyType":"self","type":"third_party","purpose":"custody",' +
        '"description":"Primary","blockchain":"ARC"}',
    )
    expect(Object.keys(JSON.parse(new TextDecoder().decode(sent)))).toEqual([
      'idempotencyKey',
      'clientEntityId',
      'custodyType',
      'type',
      'purpose',
      'description',
      'blockchain',
    ])
  })

  it('sends every required property, including an empty description', async () => {
    const { accounts, transport } = await createdClient()

    await accounts.create({
      idempotencyKey: IDEMPOTENCY_KEY,
      clientEntityId: CLIENT_ENTITY_ID,
      custodyType: 'self',
      type: 'third_party',
      purpose: 'custody',
      description: '',
      blockchain: 'ARC',
    })

    const sent = transport.sent[0]?.bodyBytes
    if (sent == null) throw new Error('no body was sent')
    expect(new TextDecoder().decode(sent)).toBe(
      `{"idempotencyKey":"${IDEMPOTENCY_KEY}","clientEntityId":"${CLIENT_ENTITY_ID}",` +
        '"custodyType":"self","type":"third_party","purpose":"custody",' +
        '"description":"","blockchain":"ARC"}',
    )
  })

  it('binds body_sha256 to the exact bytes it transmits', async () => {
    const { accounts, transport } = await createdClient()

    await accounts.create(VALID_REQUEST)

    const request = transport.sent[0]
    if (request?.bodyBytes == null) throw new Error('no body was sent')
    // Hash what went on the wire, not what the client meant to send. If
    // anything re-serialized the body between signing and transport, these
    // differ — which is the failure this whole exact-byte discipline exists to
    // make impossible.
    expect(claimsOf(request).body_sha256).toBe(toBase64Url(sha256(request.bodyBytes)))
  })

  it('decodes the documented 201 into an account', async () => {
    const { accounts } = await createdClient()

    const account = await accounts.create(VALID_REQUEST)

    expect(account.accountId).toBe('acct-1')
    expect(account.status).toEqual({ kind: 'pending' })
    expect(account.custodyType).toEqual({ kind: 'self' })
  })

  it('treats another 2xx as an API failure rather than a created account', async () => {
    const transport = new RecordingTransport({
      status: 200,
      headers: { 'X-Request-Id': 'req-200' },
      bodyBytes: envelope(CREATED_ACCOUNT),
    })
    const accounts = createDaaUserClient(
      transport,
      'production',
      signingFor(await registeredAuthKey(), AUTH_KEY_ID),
    ).accounts

    expect(await detailOf(accounts.create(VALID_REQUEST))).toEqual({
      kind: 'api',
      httpStatus: 200,
      retryable: false,
    })
  })
})

describe('local rejection', () => {
  async function rejectingClient() {
    const transport = new RecordingTransport({ status: 201, headers: {}, bodyBytes: null })
    const signing = signingFor(await registeredAuthKey(), AUTH_KEY_ID)
    return {
      accounts: createDaaUserClient(transport, 'production', signing).accounts,
      transport,
      signing,
    }
  }

  it('refuses a property the registry schema does not name, without sending it', async () => {
    const { accounts, transport, signing } = await rejectingClient()

    // `blockChain` is the realistic version of this: a near-miss of a real
    // property. Dropping it silently would create the account on the default
    // home chain while the caller believed it had chosen one.
    const detail = await detailOf(accounts.create({ ...VALID_REQUEST, blockChain: 'ARC' } as never))

    expect(detail.kind).toBe('contract_violation')
    expect(transport.sent).toHaveLength(0)
    // Nothing was signed either: an Owner signature is not spent on bytes that
    // cannot succeed.
    expect(signing.resolutions()).toBe(0)
  })

  it('refuses each field the registry constrains, without sending anything', async () => {
    const invalid: readonly CreateAccountRequest[] = [
      { ...VALID_REQUEST, idempotencyKey: 'not-a-uuid' },
      // A v1 UUID: syntactically a UUID, but the contract documents v4.
      { ...VALID_REQUEST, idempotencyKey: '22222222-2222-1222-a222-222222222222' },
      { ...VALID_REQUEST, clientEntityId: 'not-a-uuid' },
      { ...VALID_REQUEST, custodyType: 'omnibus' } as never,
      { ...VALID_REQUEST, type: 'fourth_party' } as never,
      { ...VALID_REQUEST, purpose: 'trading' } as never,
      { ...VALID_REQUEST, description: 7 } as never,
      { ...VALID_REQUEST, blockchain: '' },
      // The clientEntityId-omission case gets its own test below, which
      // checks the specific rejection reason rather than only `kind`.
      'not an object' as never,
      [] as never,
    ]

    for (const request of invalid) {
      const { accounts, transport } = await rejectingClient()
      expect((await detailOf(accounts.create(request))).kind).toBe('contract_violation')
      expect(transport.sent).toHaveLength(0)
    }
  })

  it('omits blockchain from the signed body when the caller does not supply it', async () => {
    const { accounts, transport } = await createdClient()

    // `blockchain` is optional: DAA provisions on `ARC` when it is omitted.
    // This SDK must not invent a stricter local rule than the service actually
    // enforces.
    await accounts.create({
      idempotencyKey: IDEMPOTENCY_KEY,
      clientEntityId: CLIENT_ENTITY_ID,
      custodyType: 'self',
      type: 'third_party',
      purpose: 'custody',
      description: 'Primary',
    })

    const sent = transport.sent[0]?.bodyBytes
    if (sent == null) throw new Error('no body was sent')
    expect(Object.keys(JSON.parse(new TextDecoder().decode(sent)))).toEqual([
      'idempotencyKey',
      'clientEntityId',
      'custodyType',
      'type',
      'purpose',
      'description',
    ])
  })

  it('rejects an omitted clientEntityId, not just a malformed one', async () => {
    const { accounts, transport, signing } = await rejectingClient()

    // A self-custody create requires `clientEntityId` outright; an omission is
    // a distinct defect from the malformed-UUID case above, and the message
    // names it as required, not merely as invalid.
    const withoutClientEntityId = {
      idempotencyKey: IDEMPOTENCY_KEY,
      custodyType: 'self',
      type: 'third_party',
      purpose: 'custody',
      description: 'Primary',
      blockchain: 'ARC',
    } as never

    try {
      await accounts.create(withoutClientEntityId)
      throw new Error('expected the create to be rejected')
    } catch (err) {
      if (!isDaaError(err)) throw err
      expect(err.detail.kind).toBe('contract_violation')
      expect((err as Error).message).toMatch(/clientEntityId is required/)
    }
    expect(transport.sent).toHaveLength(0)
    expect(signing.resolutions()).toBe(0)
  })

  it('rejects type=first_party, not just an unrecognized type', async () => {
    const { accounts, transport, signing } = await rejectingClient()

    // `first_party` is a real value the registry's open string would admit.
    // The contract narrows a self-custody create to `third_party` alone, so
    // this is a distinct defect from the generic-sweep `fourth_party` case,
    // which is merely a value neither side ever recognized.
    const detail = await detailOf(
      accounts.create({ ...VALID_REQUEST, type: 'first_party' } as never),
    )

    expect(detail.kind).toBe('contract_violation')
    expect(transport.sent).toHaveLength(0)
    expect(signing.resolutions()).toBe(0)
  })

  it('rejects purpose=payments, not just an unrecognized purpose', async () => {
    const { accounts, transport, signing } = await rejectingClient()

    // `payments` is a real value the registry's open string would admit. The
    // contract narrows a self-custody create to `custody` alone, so this is a
    // distinct defect from the generic-sweep `trading` case, which is merely
    // a value neither side ever recognized.
    const detail = await detailOf(
      accounts.create({ ...VALID_REQUEST, purpose: 'payments' } as never),
    )

    expect(detail.kind).toBe('contract_violation')
    expect(transport.sent).toHaveLength(0)
    expect(signing.resolutions()).toBe(0)
  })

  it('rejects a 256-character description, not just a non-string one', async () => {
    const { accounts, transport, signing } = await rejectingClient()

    // The contract caps `description` at 255 characters (`maxLength: 255`)
    // and the server enforces the same bound. One character over must fail
    // locally, before a device-authorization ceremony and idempotency key are
    // spent on a request the service would reject anyway.
    const detail = await detailOf(
      accounts.create({ ...VALID_REQUEST, description: 'a'.repeat(256) }),
    )

    expect(detail.kind).toBe('contract_violation')
    expect(transport.sent).toHaveLength(0)
    expect(signing.resolutions()).toBe(0)
  })

  it('accepts a 255-character description', async () => {
    const { accounts, transport } = await createdClient()

    await accounts.create({ ...VALID_REQUEST, description: 'a'.repeat(255) })

    expect(transport.sent).toHaveLength(1)
  })

  it('fails closed while the AuthKey is not yet registered', async () => {
    const transport = new RecordingTransport({ status: 201, headers: {}, bodyBytes: null })
    // `created`, not `existing`: Device Registration Complete has not
    // acknowledged this key, so it may sign the Complete call and nothing else.
    const authKey = await unregisteredAuthKey()
    expect(authKey.resolution()).toBe('created')
    const accounts = createDaaUserClient(
      transport,
      'production',
      signingFor(authKey, AUTH_KEY_ID),
    ).accounts

    expect(await detailOf(accounts.create(VALID_REQUEST))).toEqual({ kind: 'contract_violation' })
    expect(transport.sent).toHaveLength(0)
  })
})
