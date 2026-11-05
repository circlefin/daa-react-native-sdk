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
import type { CreateTransferRequest } from '../models/CreateTransferRequest'
import type { DaaHttpRequest, DaaHttpResponse, DaaTransport } from '../transport/DaaTransport'
import { registeredAuthKey, signingFor, unregisteredAuthKey } from './userClientSigning'

/**
 * The signed transfer create, end to end through the client. Mirrors
 * `accountsCreate.test.ts`'s structure — same discipline, different operation.
 *
 * Every wire fact here is a literal rather than a comparison against the
 * constant the production code reads, for the reason that file gives: an
 * assertion that moves with the defect catches nothing.
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
const ADDRESS_ID = '44444444-4444-4444-8444-444444444444'
const AUTH_KEY_ID = '11111111-1111-4111-8111-111111111111'

/** A complete transfer: every field the service guarantees. */
const CREATED_TRANSFER =
  '{"id":"tr-1","source":{"type":"account","id":"acct-src"},' +
  '"destination":{"type":"account","id":"acct-dst"},' +
  '"amount":{"amount":"10.25","currency":"USD"},"status":"pending"}'

const VALID_REQUEST: CreateTransferRequest = {
  idempotencyKey: IDEMPOTENCY_KEY,
  destination: { type: 'account', id: 'acct-dst' },
  amount: { amount: '10.25', currency: 'USD' },
}

function bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text)
}

function envelope(payload: string): Uint8Array {
  return bytes(`{"data":${payload}}`)
}

async function createdClient(payload = CREATED_TRANSFER) {
  const transport = new RecordingTransport({
    status: 201,
    headers: { 'X-Request-Id': 'req-create', Location: '/v1/accounts/transfers/tr-1' },
    bodyBytes: envelope(payload),
  })
  const signing = signingFor(await registeredAuthKey(), AUTH_KEY_ID)
  return { transfers: createDaaUserClient(transport, 'production', signing).transfers, transport }
}

function claimsOf(request: DaaHttpRequest): Record<string, unknown> {
  const compact = request.headers[DEVICE_AUTHORIZATION_HEADER]
  if (compact === undefined) {
    throw new Error('missing device authorization')
  }
  return JSON.parse(new TextDecoder().decode(fromBase64Url(compact.split('.')[1] ?? '')))
}

function sentBodyText(transport: RecordingTransport): string {
  const sent = transport.sent[0]?.bodyBytes
  if (sent == null) throw new Error('no body was sent')
  return new TextDecoder().decode(sent)
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
  it('posts the registry canonical path with the transfer discriminator', async () => {
    const { transfers, transport } = await createdClient()

    await transfers.create(VALID_REQUEST)

    expect(transport.sent).toHaveLength(1)
    const request = transport.sent[0]
    if (request === undefined) throw new Error('no request was sent')
    expect(request.method).toBe('POST')
    expect(request.path).toBe('/v1/accounts/transfers')
    expect(request.query).toBeNull()
    expect(request.headers['Content-Type']).toBe('application/json')
    expect(claimsOf(request)).toMatchObject({
      canonical_path: '/v1/accounts/transfers',
      method: 'POST',
      discriminator: 'transfer',
      schema_version: 1,
      aud: 'circle-digital-asset-accounts',
      idempotency_key: IDEMPOTENCY_KEY,
    })
  })

  it('sends exactly the registry properties, in the registry order, at every level', async () => {
    const { transfers, transport } = await createdClient()

    await transfers.create({
      idempotencyKey: IDEMPOTENCY_KEY,
      source: { type: 'account', id: 'acct-src' },
      destination: { type: 'account', id: 'acct-dst' },
      amount: { amount: '10.25', currency: 'USD' },
      riskSignals: { ipAddress: '198.51.100.7', deviceId: 'device-1' },
    })

    expect(sentBodyText(transport)).toBe(
      `{"idempotencyKey":"${IDEMPOTENCY_KEY}","source":{"type":"account","id":"acct-src"},` +
        '"destination":{"type":"account","id":"acct-dst"},' +
        '"amount":{"amount":"10.25","currency":"USD"},' +
        '"riskSignals":{"ipAddress":"198.51.100.7","deviceId":"device-1"}}',
    )
    const body = JSON.parse(sentBodyText(transport))
    expect(Object.keys(body)).toEqual([
      'idempotencyKey',
      'source',
      'destination',
      'amount',
      'riskSignals',
    ])
    expect(Object.keys(body.destination)).toEqual(['type', 'id'])
    expect(Object.keys(body.amount)).toEqual(['amount', 'currency'])
  })

  it('sends the verified_blockchain destination arm with its own property set', async () => {
    const { transfers, transport } = await createdClient()

    await transfers.create({
      ...VALID_REQUEST,
      destination: { type: 'verified_blockchain', addressId: ADDRESS_ID },
    })

    expect(sentBodyText(transport)).toBe(
      `{"idempotencyKey":"${IDEMPOTENCY_KEY}",` +
        `"destination":{"type":"verified_blockchain","addressId":"${ADDRESS_ID}"},` +
        '"amount":{"amount":"10.25","currency":"USD"}}',
    )
  })

  it('sends the amount as a decimal string, not a JSON number', async () => {
    const { transfers, transport } = await createdClient()

    // Eighteen significant digits: a value `JSON.stringify` would round if this
    // ever became a numeric literal, and the rounded value is what the Owner
    // would then be signing for.
    await transfers.create({
      ...VALID_REQUEST,
      amount: { amount: '1234567890123456.78', currency: 'USD' },
    })

    expect(sentBodyText(transport)).toContain('"amount":{"amount":"1234567890123456.78"')
  })

  it('snapshots amount fields before validation and serialization', async () => {
    const { transfers, transport } = await createdClient()
    let reads = 0
    const amount = { currency: 'USD' } as CreateTransferRequest['amount']
    Object.defineProperty(amount, 'amount', {
      enumerable: true,
      get: () => {
        reads += 1
        return reads === 1 ? '10.25' : '999.99'
      },
    })

    await transfers.create({ ...VALID_REQUEST, amount })

    expect(reads).toBe(1)
    expect(sentBodyText(transport)).toContain('"amount":{"amount":"10.25","currency":"USD"}')
  })

  it('snapshots source and destination fields before validation and serialization', async () => {
    const { transfers, transport } = await createdClient()
    const reads = {
      sourceType: 0,
      sourceId: 0,
      destinationType: 0,
      destinationId: 0,
    }
    const source = new Proxy(
      { type: 'account' as const, id: 'acct-src' },
      {
        get(target, property, receiver) {
          if (property === 'type') reads.sourceType += 1
          if (property === 'id') reads.sourceId += 1
          return Reflect.get(target, property, receiver)
        },
      },
    )
    const destination = new Proxy(
      { type: 'account' as const, id: 'acct-dst' },
      {
        get(target, property, receiver) {
          if (property === 'type') reads.destinationType += 1
          if (property === 'id') reads.destinationId += 1
          return Reflect.get(target, property, receiver)
        },
      },
    )

    await transfers.create({ ...VALID_REQUEST, source, destination })

    expect(reads).toEqual({ sourceType: 1, sourceId: 1, destinationType: 1, destinationId: 1 })
    expect(sentBodyText(transport)).toContain(
      '"source":{"type":"account","id":"acct-src"},"destination":{"type":"account","id":"acct-dst"}',
    )
  })

  it('snapshots the verified destination fields before validation and serialization', async () => {
    const { transfers, transport } = await createdClient()
    const reads = { type: 0, addressId: 0 }
    const destination = new Proxy(
      { type: 'verified_blockchain' as const, addressId: ADDRESS_ID },
      {
        get(target, property, receiver) {
          if (property === 'type') reads.type += 1
          if (property === 'addressId') reads.addressId += 1
          return Reflect.get(target, property, receiver)
        },
      },
    )

    await transfers.create({ ...VALID_REQUEST, destination })

    expect(reads).toEqual({ type: 1, addressId: 1 })
    expect(sentBodyText(transport)).toContain(
      `"destination":{"type":"verified_blockchain","addressId":"${ADDRESS_ID}"}`,
    )
  })

  it('binds body_sha256 to the exact bytes it transmits', async () => {
    const { transfers, transport } = await createdClient()

    await transfers.create(VALID_REQUEST)

    const request = transport.sent[0]
    if (request?.bodyBytes == null) throw new Error('no body was sent')
    expect(claimsOf(request).body_sha256).toBe(toBase64Url(sha256(request.bodyBytes)))
  })

  it('decodes the documented 201 into a transfer', async () => {
    const { transfers } = await createdClient()

    const transfer = await transfers.create(VALID_REQUEST)

    expect(transfer.id).toBe('tr-1')
    expect(transfer.status).toEqual({ kind: 'pending' })
    expect(transfer.amount.amount).toBe('10.25')
  })

  it('treats another 2xx as an API failure rather than a created transfer', async () => {
    const transport = new RecordingTransport({
      status: 202,
      headers: { 'X-Request-Id': 'req-202' },
      bodyBytes: envelope(CREATED_TRANSFER),
    })
    const transfers = createDaaUserClient(
      transport,
      'production',
      signingFor(await registeredAuthKey(), AUTH_KEY_ID),
    ).transfers

    expect(await detailOf(transfers.create(VALID_REQUEST))).toEqual({
      kind: 'api',
      httpStatus: 202,
      retryable: false,
    })
  })
})

describe('local rejection', () => {
  async function rejectingClient() {
    const transport = new RecordingTransport({ status: 201, headers: {}, bodyBytes: null })
    const signing = signingFor(await registeredAuthKey(), AUTH_KEY_ID)
    return {
      transfers: createDaaUserClient(transport, 'production', signing).transfers,
      transport,
      signing,
    }
  }

  it('refuses a property the registry schema does not name, at any level', async () => {
    const unknownProperties: readonly CreateTransferRequest[] = [
      { ...VALID_REQUEST, memo: 'rent' } as never,
      { ...VALID_REQUEST, destination: { type: 'account', id: 'acct-dst', chain: 'ARC' } } as never,
      { ...VALID_REQUEST, amount: { amount: '10.25', currency: 'USD', scale: 2 } } as never,
      { ...VALID_REQUEST, riskSignals: { ip: '198.51.100.7' } } as never,
    ]

    for (const request of unknownProperties) {
      const { transfers, transport, signing } = await rejectingClient()
      expect((await detailOf(transfers.create(request))).kind).toBe('contract_violation')
      expect(transport.sent).toHaveLength(0)
      // Nothing was signed either: an Owner signature is not spent on bytes
      // that cannot succeed.
      expect(signing.resolutions()).toBe(0)
    }
  })

  it('refuses each field the registry constrains, without sending anything', async () => {
    const invalid: readonly CreateTransferRequest[] = [
      { ...VALID_REQUEST, idempotencyKey: 'not-a-uuid' },
      { ...VALID_REQUEST, destination: { type: 'account', id: '' } },
      { ...VALID_REQUEST, destination: { type: 'blockchain', address: '0x1' } } as never,
      { ...VALID_REQUEST, destination: { type: 'verified_blockchain', addressId: 'nope' } },
      { ...VALID_REQUEST, source: { type: 'blockchain', id: 'x' } } as never,
      // A JSON number, which is exactly what the string form exists to avoid.
      { ...VALID_REQUEST, amount: { amount: 10.25, currency: 'USD' } } as never,
      { ...VALID_REQUEST, amount: { amount: '10.25', currency: '' } },
      { ...VALID_REQUEST, amount: { amount: 'ten', currency: 'USD' } },
      { ...VALID_REQUEST, riskSignals: { ipAddress: '' } },
      'not an object' as never,
    ]

    for (const request of invalid) {
      const { transfers, transport } = await rejectingClient()
      expect((await detailOf(transfers.create(request))).kind).toBe('contract_violation')
      expect(transport.sent).toHaveLength(0)
    }
  })

  it('fails closed while the AuthKey is not yet registered', async () => {
    const transport = new RecordingTransport({ status: 201, headers: {}, bodyBytes: null })
    // `created`, not `existing`: Device Registration Complete has not
    // acknowledged this key, so it may sign the Complete call and nothing else.
    const authKey = await unregisteredAuthKey()
    expect(authKey.resolution()).toBe('created')
    const transfers = createDaaUserClient(
      transport,
      'production',
      signingFor(authKey, AUTH_KEY_ID),
    ).transfers

    expect(await detailOf(transfers.create(VALID_REQUEST))).toEqual({ kind: 'contract_violation' })
    expect(transport.sent).toHaveLength(0)
  })
})
