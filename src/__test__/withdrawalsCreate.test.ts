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
import type { CreateWithdrawalRequest } from '../models/CreateWithdrawalRequest'
import type { DaaHttpRequest, DaaHttpResponse, DaaTransport } from '../transport/DaaTransport'
import { registeredAuthKey, signingFor, unregisteredAuthKey } from './userClientSigning'

/**
 * The signed withdrawal create, end to end through the client. Mirrors
 * `transfersCreate.test.ts`'s structure — same discipline, different operation.
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

const IDEMPOTENCY_KEY = '33333333-3333-4333-a333-333333333333'
const DESTINATION_ID = '55555555-5555-4555-8555-555555555555'
const AUTH_KEY_ID = '11111111-1111-4111-8111-111111111111'

/** A complete withdrawal: every field the service guarantees. */
const CREATED_WITHDRAWAL =
  '{"id":"w-1","sourceAccountId":"acct-src",' +
  '"destination":{"type":"wire","id":"55555555-5555-4555-8555-555555555555"},' +
  '"amount":{"amount":"10.25","currency":"USD"},"status":"pending",' +
  '"createDate":"2026-01-01T00:00:00Z"}'

const VALID_REQUEST: CreateWithdrawalRequest = {
  idempotencyKey: IDEMPOTENCY_KEY,
  destination: { type: 'wire', id: DESTINATION_ID },
  amount: { amount: '10.25', currency: 'USD' },
}

function bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text)
}

function envelope(payload: string): Uint8Array {
  return bytes(`{"data":${payload}}`)
}

async function createdClient(payload = CREATED_WITHDRAWAL) {
  const transport = new RecordingTransport({
    status: 201,
    headers: { 'X-Request-Id': 'req-create', Location: '/v1/accounts/withdrawals/w-1' },
    bodyBytes: envelope(payload),
  })
  const signing = signingFor(await registeredAuthKey(), AUTH_KEY_ID)
  return {
    withdrawals: createDaaUserClient(transport, 'production', signing).withdrawals,
    transport,
  }
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
  it('posts the registry canonical path with the withdrawal discriminator', async () => {
    const { withdrawals, transport } = await createdClient()

    await withdrawals.create(VALID_REQUEST)

    expect(transport.sent).toHaveLength(1)
    const request = transport.sent[0]
    if (request === undefined) throw new Error('no request was sent')
    expect(request.method).toBe('POST')
    expect(request.path).toBe('/v1/accounts/withdrawals')
    expect(request.query).toBeNull()
    expect(request.headers['Content-Type']).toBe('application/json')
    expect(claimsOf(request)).toMatchObject({
      canonical_path: '/v1/accounts/withdrawals',
      method: 'POST',
      discriminator: 'withdrawal',
      schema_version: 1,
      aud: 'circle-digital-asset-accounts',
      idempotency_key: IDEMPOTENCY_KEY,
    })
  })

  it('sends exactly the registry properties, in the registry order, at every level', async () => {
    const { withdrawals, transport } = await createdClient()

    await withdrawals.create({
      idempotencyKey: IDEMPOTENCY_KEY,
      source: { type: 'account', id: 'acct-src' },
      destination: { type: 'wire', id: DESTINATION_ID, name: 'My Bank' },
      amount: { amount: '10.25', currency: 'USD' },
      toAmount: { amount: '9.00', currency: 'EUR' },
      riskSignals: { ipAddress: '198.51.100.7', deviceId: 'device-1' },
      burnAll: true,
    })

    expect(sentBodyText(transport)).toBe(
      `{"idempotencyKey":"${IDEMPOTENCY_KEY}","source":{"type":"account","id":"acct-src"},` +
        `"destination":{"type":"wire","id":"${DESTINATION_ID}","name":"My Bank"},` +
        '"amount":{"amount":"10.25","currency":"USD"},' +
        '"toAmount":{"amount":"9.00","currency":"EUR"},' +
        '"riskSignals":{"ipAddress":"198.51.100.7","deviceId":"device-1"},' +
        '"burnAll":true}',
    )
    const body = JSON.parse(sentBodyText(transport))
    expect(Object.keys(body)).toEqual([
      'idempotencyKey',
      'source',
      'destination',
      'amount',
      'toAmount',
      'riskSignals',
      'burnAll',
    ])
    expect(Object.keys(body.destination)).toEqual(['type', 'id', 'name'])
    expect(Object.keys(body.amount)).toEqual(['amount', 'currency'])
    expect(Object.keys(body.toAmount)).toEqual(['amount', 'currency'])
  })

  it('sends the ach destination arm with the same property set as wire', async () => {
    const { withdrawals, transport } = await createdClient()

    await withdrawals.create({ ...VALID_REQUEST, destination: { type: 'ach', id: DESTINATION_ID } })

    expect(sentBodyText(transport)).toBe(
      `{"idempotencyKey":"${IDEMPOTENCY_KEY}",` +
        `"destination":{"type":"ach","id":"${DESTINATION_ID}"},` +
        '"amount":{"amount":"10.25","currency":"USD"}}',
    )
  })

  it('omits toAmount.amount when the caller lets DAA resolve the conversion', async () => {
    const { withdrawals, transport } = await createdClient()

    await withdrawals.create({ ...VALID_REQUEST, toAmount: { currency: 'EUR' } })

    expect(sentBodyText(transport)).toContain('"toAmount":{"currency":"EUR"}')
  })

  it('sends the amount as a decimal string, not a JSON number', async () => {
    const { withdrawals, transport } = await createdClient()

    // Eighteen significant digits: a value `JSON.stringify` would round if this
    // ever became a numeric literal, and the rounded value is what the Owner
    // would then be signing for.
    await withdrawals.create({
      ...VALID_REQUEST,
      amount: { amount: '1234567890123456.78', currency: 'USD' },
    })

    expect(sentBodyText(transport)).toContain('"amount":{"amount":"1234567890123456.78"')
  })

  it('snapshots amount fields before validation and serialization', async () => {
    const { withdrawals, transport } = await createdClient()
    let reads = 0
    const amount = { currency: 'USD' } as CreateWithdrawalRequest['amount']
    Object.defineProperty(amount, 'amount', {
      enumerable: true,
      get: () => {
        reads += 1
        return reads === 1 ? '10.25' : '999.99'
      },
    })

    await withdrawals.create({ ...VALID_REQUEST, amount })

    expect(reads).toBe(1)
    expect(sentBodyText(transport)).toContain('"amount":{"amount":"10.25","currency":"USD"}')
  })

  it('snapshots source, destination, and toAmount fields before serialization', async () => {
    const { withdrawals, transport } = await createdClient()
    const reads = {
      sourceType: 0,
      sourceId: 0,
      destinationType: 0,
      destinationId: 0,
      destinationName: 0,
      toAmount: 0,
      toCurrency: 0,
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
      { type: 'wire' as const, id: DESTINATION_ID, name: 'My Bank' },
      {
        get(target, property, receiver) {
          if (property === 'type') reads.destinationType += 1
          if (property === 'id') reads.destinationId += 1
          if (property === 'name') reads.destinationName += 1
          return Reflect.get(target, property, receiver)
        },
      },
    )
    const toAmount = new Proxy(
      { amount: '9.00', currency: 'EUR' as const },
      {
        get(target, property, receiver) {
          if (property === 'amount') reads.toAmount += 1
          if (property === 'currency') reads.toCurrency += 1
          return Reflect.get(target, property, receiver)
        },
      },
    )

    await withdrawals.create({ ...VALID_REQUEST, source, destination, toAmount })

    expect(reads).toEqual({
      sourceType: 1,
      sourceId: 1,
      destinationType: 1,
      destinationId: 1,
      destinationName: 1,
      toAmount: 1,
      toCurrency: 1,
    })
    expect(sentBodyText(transport)).toContain(
      '"source":{"type":"account","id":"acct-src"},' +
        `"destination":{"type":"wire","id":"${DESTINATION_ID}","name":"My Bank"},` +
        '"amount":{"amount":"10.25","currency":"USD"},' +
        '"toAmount":{"amount":"9.00","currency":"EUR"}',
    )
  })

  it('binds body_sha256 to the exact bytes it transmits', async () => {
    const { withdrawals, transport } = await createdClient()

    await withdrawals.create(VALID_REQUEST)

    const request = transport.sent[0]
    if (request?.bodyBytes == null) throw new Error('no body was sent')
    expect(claimsOf(request).body_sha256).toBe(toBase64Url(sha256(request.bodyBytes)))
  })

  it('decodes the documented 201 into a withdrawal detail', async () => {
    const { withdrawals } = await createdClient()

    const withdrawal = await withdrawals.create(VALID_REQUEST)

    expect(withdrawal.id).toBe('w-1')
    expect(withdrawal.status).toEqual({ kind: 'pending' })
    expect(withdrawal.amount.amount).toBe('10.25')
  })

  it('treats another 2xx as an API failure rather than a created withdrawal', async () => {
    const transport = new RecordingTransport({
      status: 202,
      headers: { 'X-Request-Id': 'req-202' },
      bodyBytes: envelope(CREATED_WITHDRAWAL),
    })
    const withdrawals = createDaaUserClient(
      transport,
      'production',
      signingFor(await registeredAuthKey(), AUTH_KEY_ID),
    ).withdrawals

    expect(await detailOf(withdrawals.create(VALID_REQUEST))).toEqual({
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
      withdrawals: createDaaUserClient(transport, 'production', signing).withdrawals,
      transport,
      signing,
    }
  }

  it('refuses a property the registry schema does not name, at any level', async () => {
    const unknownProperties: readonly CreateWithdrawalRequest[] = [
      { ...VALID_REQUEST, memo: 'rent' } as never,
      {
        ...VALID_REQUEST,
        destination: { type: 'wire', id: DESTINATION_ID, chain: 'ARC' },
      } as never,
      { ...VALID_REQUEST, amount: { amount: '10.25', currency: 'USD', scale: 2 } } as never,
      { ...VALID_REQUEST, toAmount: { currency: 'USD', fee: '1.00' } } as never,
      { ...VALID_REQUEST, riskSignals: { ip: '198.51.100.7' } } as never,
    ]

    for (const request of unknownProperties) {
      const { withdrawals, transport, signing } = await rejectingClient()
      expect((await detailOf(withdrawals.create(request))).kind).toBe('contract_violation')
      expect(transport.sent).toHaveLength(0)
      // Nothing was signed either: an Owner signature is not spent on bytes
      // that cannot succeed.
      expect(signing.resolutions()).toBe(0)
    }
  })

  it('refuses each field the registry constrains, without sending anything', async () => {
    const invalid: readonly CreateWithdrawalRequest[] = [
      { ...VALID_REQUEST, idempotencyKey: 'not-a-uuid' },
      { ...VALID_REQUEST, destination: { type: 'wire', id: 'not-a-uuid' } },
      { ...VALID_REQUEST, destination: { type: 'ach', id: '' } as never },
      { ...VALID_REQUEST, destination: { type: 'check', id: DESTINATION_ID } } as never,
      { ...VALID_REQUEST, destination: { type: 'wire', id: DESTINATION_ID, name: '' } },
      { ...VALID_REQUEST, source: { type: 'blockchain', id: 'x' } } as never,
      // A JSON number, which is exactly what the string form exists to avoid.
      { ...VALID_REQUEST, amount: { amount: 10.25, currency: 'USD' } } as never,
      { ...VALID_REQUEST, amount: { amount: '10.25', currency: '' } },
      { ...VALID_REQUEST, amount: { amount: 'ten', currency: 'USD' } },
      { ...VALID_REQUEST, toAmount: { currency: 'GBP' } } as never,
      { ...VALID_REQUEST, toAmount: { amount: 9.0, currency: 'USD' } } as never,
      { ...VALID_REQUEST, riskSignals: { ipAddress: '' } },
      { ...VALID_REQUEST, burnAll: 'yes' } as never,
      'not an object' as never,
    ]

    for (const request of invalid) {
      const { withdrawals, transport } = await rejectingClient()
      expect((await detailOf(withdrawals.create(request))).kind).toBe('contract_violation')
      expect(transport.sent).toHaveLength(0)
    }
  })

  it('fails closed while the AuthKey is not yet registered', async () => {
    const transport = new RecordingTransport({ status: 201, headers: {}, bodyBytes: null })
    // `created`, not `existing`: Device Registration Complete has not
    // acknowledged this key, so it may sign the Complete call and nothing else.
    const authKey = await unregisteredAuthKey()
    expect(authKey.resolution()).toBe('created')
    const withdrawals = createDaaUserClient(
      transport,
      'production',
      signingFor(authKey, AUTH_KEY_ID),
    ).withdrawals

    expect(await detailOf(withdrawals.create(VALID_REQUEST))).toEqual({
      kind: 'contract_violation',
    })
    expect(transport.sent).toHaveLength(0)
  })
})
