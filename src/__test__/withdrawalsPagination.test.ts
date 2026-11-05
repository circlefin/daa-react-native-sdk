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
import type { DaaHttpRequest, DaaHttpResponse, DaaTransport } from '../transport/DaaTransport'

/**
 * The withdrawal list, end to end through the client. Mirrors
 * `transfersPagination.test.ts`'s structure — same discipline, different
 * resource. Every wire fact here is a literal, and every test also confirms
 * `list()` does not resolve the AuthKey: `NO_SIGNING` throws if it tries, the
 * same guard `withdrawalsClient.test.ts`'s `get` tests use.
 */

const ORIGIN = 'https://api.circle.com'
const CURSOR_AFTER = '3f1a2b4c-5d6e-4f70-8192-a3b4c5d6e7f8'
const CURSOR_BEFORE = '4f1a2b4c-5d6e-4f70-8192-a3b4c5d6e7f8'
const WITHDRAWAL =
  '{"id":"a49f9b1d-75e0-44a9-b8d2-4293b3f11ebd","sourceAccountId":"1000662322",' +
  '"destination":{"type":"wire","id":"0db1c81a-d36d-4777-8774-9682d96d82c8"},' +
  '"amount":{"amount":"10.00","currency":"USD"},"status":"pending",' +
  '"createDate":"2026-01-01T00:00:00Z"}'

function bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text)
}

function pageBody(withdrawal = WITHDRAWAL): Uint8Array {
  return bytes(`{"data":[${withdrawal}]}`)
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

describe('withdrawals pagination', () => {
  it('loads and freezes withdrawals over the exact public collection path, unsigned', async () => {
    const transport = new SequenceTransport([response()])
    // `NO_SIGNING` throws if `list()` ever asks for the AuthKey — a read must
    // not sign, unlike `create`.
    const page = await createDaaUserClient(transport, 'production', NO_SIGNING).withdrawals.list()

    expect(transport.sent).toEqual([
      {
        method: 'GET',
        path: '/v1/accounts/withdrawals',
        query: null,
        headers: {},
        bodyBytes: null,
      },
    ])
    expect(page.items[0]?.id).toBe('a49f9b1d-75e0-44a9-b8d2-4293b3f11ebd')
    expect(page.items[0]?.destination.type).toEqual({ kind: 'wire' })
    expect(page.items[0]?.status).toEqual({ kind: 'pending' })
    expect(Object.isFrozen(page)).toBe(true)
    expect(Object.isFrozen(page.items)).toBe(true)
    expect(Object.isFrozen(page.items[0])).toBe(true)
    await expect(page.next()).resolves.toBeNull()
    await expect(page.previous()).resolves.toBeNull()
  })

  it('serializes the documented withdrawal filters in deterministic order', async () => {
    const transport = new SequenceTransport([response()])
    const withdrawals = createDaaUserClient(transport, 'production', NO_SIGNING).withdrawals

    await withdrawals.list({
      custodyType: 'segregated',
      accountId: '1000662322',
      status: ['pending', 'failed'],
      from: '2026-08-01T00:00:00Z',
      to: '2026-08-18T00:00:00Z',
      pageAfter: CURSOR_AFTER,
      pageSize: 50,
    })

    expect(transport.sent[0]?.query).toBe(
      'custodyType=segregated&accountId=1000662322&status=pending&status=failed' +
        '&from=2026-08-01T00%3A00%3A00Z&to=2026-08-18T00%3A00%3A00Z' +
        `&pageAfter=${CURSOR_AFTER}&pageSize=50`,
    )
  })

  it('follows only the same withdrawal collection and preserves its opaque query', async () => {
    const nextQuery = 'z=last&pageAfter=backing%2Fcursor%3D&repeat=1&repeat=2&reserved=%2B%26'
    const previousQuery = 'pageBefore=opaque-value&pageSize=2'
    const transport = new SequenceTransport([
      response({
        Link:
          `<${ORIGIN}/v1/accounts/withdrawals?${nextQuery}>; rel="next", ` +
          `<${ORIGIN}/v1/accounts/withdrawals?${previousQuery}>; rel="prev"`,
      }),
      response(),
      response(),
    ])

    const page = await createDaaUserClient(transport, 'production', NO_SIGNING).withdrawals.list()
    await page.next()
    await page.previous()

    expect(transport.sent[1]?.query).toBe(nextQuery)
    expect(transport.sent[2]?.query).toBe(previousQuery)
    for (const request of transport.sent) {
      expect(request.path).toBe('/v1/accounts/withdrawals')
      expect(request.method).toBe('GET')
      expect(request.bodyBytes).toBeNull()
    }
  })

  it.each([
    `${ORIGIN}/v1/accounts?pageAfter=${CURSOR_AFTER}`,
    `${ORIGIN}/v1/accounts/transfers?pageAfter=${CURSOR_AFTER}`,
    `https://evil.example/v1/accounts/withdrawals?pageAfter=${CURSOR_AFTER}`,
  ])('rejects navigation outside the trusted withdrawal collection: %s', async (target) => {
    const transport = new SequenceTransport([response({ Link: `<${target}>; rel="next"` })])

    const detail = await detailOf(
      createDaaUserClient(transport, 'production', NO_SIGNING).withdrawals.list(),
    )

    expect(detail.kind).toBe('contract_violation')
    expect(transport.sent).toHaveLength(1)
  })

  it('uses the configured environment as the pagination trust anchor', async () => {
    const transport = new SequenceTransport([
      response({ Link: `<${ORIGIN}/v1/accounts/withdrawals?pageAfter=x>; rel="next"` }),
    ])

    const detail = await detailOf(
      createDaaUserClient(transport, 'sandbox', NO_SIGNING).withdrawals.list(),
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
    { custodyType: 'unknown' },
    { accountId: '' },
    { status: [] },
    { status: ['unknown'] },
    { from: '' },
    { to: '' },
    { pageSize: 0 },
    { pageSize: 1.5 },
  ])('rejects an invalid initial query without sending it: %o', async (query) => {
    const transport = new SequenceTransport([])
    const withdrawals = createDaaUserClient(transport, 'production', NO_SIGNING).withdrawals

    expect((await detailOf(withdrawals.list(query as never))).kind).toBe('contract_violation')
    expect(transport.sent).toHaveLength(0)
  })

  it('maps malformed list bodies and undocumented success statuses through shared rules', async () => {
    const malformed = new SequenceTransport([
      { status: 200, headers: { 'X-Request-Id': 'req-list' }, bodyBytes: bytes('{"data":{}}') },
    ])
    await expect(
      detailOf(createDaaUserClient(malformed, 'production', NO_SIGNING).withdrawals.list()),
    ).resolves.toEqual({ kind: 'contract_violation', correlationId: 'req-list' })

    const malformedItem = new SequenceTransport([
      { status: 200, headers: { 'X-Request-Id': 'req-item' }, bodyBytes: bytes('{"data":[{}]}') },
    ])
    await expect(
      detailOf(createDaaUserClient(malformedItem, 'production', NO_SIGNING).withdrawals.list()),
    ).resolves.toEqual({ kind: 'contract_violation', correlationId: 'req-item' })

    const wrongStatus = new SequenceTransport([{ status: 201, headers: {}, bodyBytes: pageBody() }])
    await expect(
      detailOf(createDaaUserClient(wrongStatus, 'production', NO_SIGNING).withdrawals.list()),
    ).resolves.toMatchObject({ kind: 'api', httpStatus: 201 })
  })
})
