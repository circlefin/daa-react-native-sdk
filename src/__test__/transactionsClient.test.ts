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
import { NO_SIGNING } from './userClientSigning'
import { isDaaError } from '../errors'
import type { DaaSdkError } from '../errors'
import { TransactionBlockchainLocation } from '../models/Transaction'
import type { DaaHttpRequest, DaaHttpResponse, DaaTransport } from '../transport/DaaTransport'

const ORIGIN = 'https://api.circle.com'
const CURSOR_AFTER = '3f1a2b4c-5d6e-4f70-8192-a3b4c5d6e7f8'
const CURSOR_BEFORE = '4f1a2b4c-5d6e-4f70-8192-a3b4c5d6e7f8'
const CLIENT_ENTITY_ID = '5f1a2b4c-5d6e-4f70-8192-a3b4c5d6e7f8'
const TRANSACTION =
  '{"id":"txn-1","type":"transfer","status":"pending",' +
  '"amount":{"amount":"10.00","currency":"USDC"},' +
  '"source":{"type":"account","id":"1000662322"},' +
  '"destination":{"type":"blockchain","chain":"ETH","address":"0xdest"},' +
  '"createDate":"2026-01-01T00:00:00Z","updateDate":"2026-01-02T00:00:00Z"}'

function bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text)
}

function pageBody(transaction = TRANSACTION): Uint8Array {
  return bytes(`{"data":[${transaction}]}`)
}

class SequenceTransport implements DaaTransport {
  readonly sent: DaaHttpRequest[] = []

  constructor(private readonly responses: readonly DaaHttpResponse[]) {}

  async send(request: DaaHttpRequest): Promise<DaaHttpResponse> {
    this.sent.push(request)
    const response = this.responses[this.sent.length - 1]
    if (response === undefined) throw new Error('unexpected request')
    return response
  }
}

function response(headers: Readonly<Record<string, string>> = {}): DaaHttpResponse {
  return { status: 200, headers, bodyBytes: pageBody() }
}

async function detailOf(operation: Promise<unknown>): Promise<DaaSdkError> {
  try {
    await operation
  } catch (err) {
    if (isDaaError(err)) return err.detail
    throw err
  }
  throw new Error('expected the operation to fail')
}

describe('transactions list', () => {
  it('loads and freezes transactions over the exact public collection path', async () => {
    const transport = new SequenceTransport([response()])
    const page = await createDaaUserClient(transport, 'production', NO_SIGNING).transactions.list()

    expect(transport.sent).toEqual([
      {
        method: 'GET',
        path: '/v1/accounts/transactions',
        query: null,
        headers: {},
        bodyBytes: null,
      },
    ])
    expect(page.items[0]?.id).toBe('txn-1')
    expect(page.items[0]?.type).toEqual({ kind: 'transfer' })
    expect(page.items[0]?.destination).toBeInstanceOf(TransactionBlockchainLocation)
    expect(Object.isFrozen(page)).toBe(true)
    expect(Object.isFrozen(page.items)).toBe(true)
    expect(Object.isFrozen(page.items[0])).toBe(true)
    await expect(page.next()).resolves.toBeNull()
    await expect(page.previous()).resolves.toBeNull()
  })

  it('serializes the documented transaction filters in deterministic order', async () => {
    const transport = new SequenceTransport([response()])
    const transactions = createDaaUserClient(transport, 'production', NO_SIGNING).transactions

    await transactions.list({
      custodyType: 'segregated',
      accountId: '1000662322',
      clientEntityId: CLIENT_ENTITY_ID,
      isAttributed: true,
      type: ['transfer', 'deposit'],
      status: ['pending', 'complete'],
      currency: 'USDC',
      from: '2026-08-01T00:00:00Z',
      to: '2026-08-18T00:00:00Z',
      pageAfter: CURSOR_AFTER,
      pageSize: 50,
    })

    expect(transport.sent[0]?.query).toBe(
      'custodyType=segregated&accountId=1000662322' +
        `&clientEntityId=${CLIENT_ENTITY_ID}&isAttributed=true` +
        '&type=transfer&type=deposit&status=pending&status=complete' +
        '&currency=USDC' +
        '&from=2026-08-01T00%3A00%3A00Z&to=2026-08-18T00%3A00%3A00Z' +
        `&pageAfter=${CURSOR_AFTER}&pageSize=50`,
    )
  })

  it('follows only the same transaction collection and preserves its opaque query', async () => {
    const nextQuery = 'z=last&pageAfter=backing%2Fcursor%3D&repeat=1&repeat=2&reserved=%2B%26'
    const previousQuery = 'pageBefore=opaque-value&pageSize=2'
    const transport = new SequenceTransport([
      response({
        Link:
          `<${ORIGIN}/v1/accounts/transactions?${nextQuery}>; rel="next", ` +
          `<${ORIGIN}/v1/accounts/transactions?${previousQuery}>; rel="prev"`,
      }),
      response(),
      response(),
    ])

    const page = await createDaaUserClient(transport, 'production', NO_SIGNING).transactions.list()
    await page.next()
    await page.previous()

    expect(transport.sent[1]?.query).toBe(nextQuery)
    expect(transport.sent[2]?.query).toBe(previousQuery)
    for (const request of transport.sent) {
      expect(request.path).toBe('/v1/accounts/transactions')
      expect(request.method).toBe('GET')
      expect(request.bodyBytes).toBeNull()
    }
  })

  it.each([
    `${ORIGIN}/v1/accounts?pageAfter=${CURSOR_AFTER}`,
    `${ORIGIN}/v1/accounts/transfers?pageAfter=${CURSOR_AFTER}`,
    `https://evil.example/v1/accounts/transactions?pageAfter=${CURSOR_AFTER}`,
  ])('rejects navigation outside the trusted transaction collection: %s', async (target) => {
    const transport = new SequenceTransport([response({ Link: `<${target}>; rel="next"` })])

    const detail = await detailOf(
      createDaaUserClient(transport, 'production', NO_SIGNING).transactions.list(),
    )

    expect(detail.kind).toBe('contract_violation')
    expect(transport.sent).toHaveLength(1)
  })

  it('uses the configured environment as the pagination trust anchor', async () => {
    const transport = new SequenceTransport([
      response({ Link: `<${ORIGIN}/v1/accounts/transactions?pageAfter=x>; rel="next"` }),
    ])

    const detail = await detailOf(
      createDaaUserClient(transport, 'sandbox', NO_SIGNING).transactions.list(),
    )

    expect(detail.kind).toBe('contract_violation')
    expect(transport.sent).toHaveLength(1)
  })

  it.each([
    null,
    [],
    { pageAfter: CURSOR_AFTER, pageBefore: CURSOR_BEFORE },
    { pageAfter: 'not-a-uuid' },
    { pageBefore: 'not-a-uuid' },
    { clientEntityId: 'not-a-uuid' },
    { custodyType: 'unknown' },
    { type: ['wallet'] },
    { status: ['settling'] },
    { accountId: '' },
    { currency: '' },
    { from: '' },
    { to: '' },
    { isAttributed: 'true' },
    { pageSize: 0 },
    { pageSize: 1.5 },
  ])('rejects an invalid initial query without sending it: %o', async (query) => {
    const transport = new SequenceTransport([])
    const transactions = createDaaUserClient(transport, 'production', NO_SIGNING).transactions

    expect((await detailOf(transactions.list(query as never))).kind).toBe('contract_violation')
    expect(transport.sent).toHaveLength(0)
  })

  it('maps malformed list bodies and undocumented success statuses through shared rules', async () => {
    const malformed = new SequenceTransport([
      { status: 200, headers: { 'X-Request-Id': 'req-list' }, bodyBytes: bytes('{"data":{}}') },
    ])
    await expect(
      detailOf(createDaaUserClient(malformed, 'production', NO_SIGNING).transactions.list()),
    ).resolves.toEqual({ kind: 'contract_violation', correlationId: 'req-list' })

    const malformedItem = new SequenceTransport([
      { status: 200, headers: { 'X-Request-Id': 'req-item' }, bodyBytes: bytes('{"data":[{}]}') },
    ])
    await expect(
      detailOf(createDaaUserClient(malformedItem, 'production', NO_SIGNING).transactions.list()),
    ).resolves.toEqual({ kind: 'contract_violation', correlationId: 'req-item' })

    const wrongStatus = new SequenceTransport([{ status: 201, headers: {}, bodyBytes: pageBody() }])
    await expect(
      detailOf(createDaaUserClient(wrongStatus, 'production', NO_SIGNING).transactions.list()),
    ).resolves.toMatchObject({ kind: 'api', httpStatus: 201 })
  })
})
