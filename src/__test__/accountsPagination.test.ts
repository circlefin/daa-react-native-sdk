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

const ORIGIN = 'https://api.circle.com'
const ACCOUNT =
  '{"accountId":"acct-1","balances":[],"entityId":"entity-1","purpose":"custody",' +
  '"status":"active","type":"first_party","custodyType":"self"}'

function bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text)
}

function pageBody(account = ACCOUNT): Uint8Array {
  return bytes(`{"data":[${account}]}`)
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

describe('accounts pagination', () => {
  it('loads and freezes the first page over the public collection path', async () => {
    const transport = new SequenceTransport([response()])
    const page = await createDaaUserClient(transport, 'production', NO_SIGNING).accounts.list()

    expect(transport.sent).toEqual([
      { method: 'GET', path: '/v1/accounts', query: null, headers: {}, bodyBytes: null },
    ])
    expect(page.items).toHaveLength(1)
    expect(page.items[0]?.accountId).toBe('acct-1')
    expect(Object.isFrozen(page)).toBe(true)
    expect(Object.isFrozen(page.items)).toBe(true)
    expect(Object.keys(page)).toEqual(['items'])
    expect(JSON.stringify(page)).not.toContain('api.circle.com')
    await expect(page.next()).resolves.toBeNull()
    await expect(page.previous()).resolves.toBeNull()
    expect(transport.sent).toHaveLength(1)
  })

  it('serializes the documented account filters in one deterministic query', async () => {
    const transport = new SequenceTransport([response()])
    const accounts = createDaaUserClient(transport, 'production', NO_SIGNING).accounts

    await accounts.list({
      custodyType: 'self',
      clientEntityId: '3f1a2b4c-5d6e-4f70-8192-a3b4c5d6e7f8',
      type: 'third_party',
      isAttributed: true,
      purpose: 'custody',
      status: ['active', 'pending'],
      description: 'primary & reserve',
      currencies: ['USD', 'EUR'],
      groupId: '4f1a2b4c-5d6e-4f70-8192-a3b4c5d6e7f8',
      from: '2026-08-01T00:00:00Z',
      to: '2026-08-18T00:00:00Z',
      pageAfter: 'opaque/selector=1',
      pageSize: 50,
    })

    expect(transport.sent[0]?.query).toBe(
      'custodyType=self&clientEntityId=3f1a2b4c-5d6e-4f70-8192-a3b4c5d6e7f8' +
        '&type=third_party&isAttributed=true&purpose=custody&status=active&status=pending' +
        '&description=primary%20%26%20reserve&currencies=USD&currencies=EUR' +
        '&groupId=4f1a2b4c-5d6e-4f70-8192-a3b4c5d6e7f8' +
        '&from=2026-08-01T00%3A00%3A00Z&to=2026-08-18T00%3A00%3A00Z' +
        '&pageAfter=opaque%2Fselector%3D1&pageSize=50',
    )
  })

  it('round-trips opaque link queries without parsing, sorting, or re-encoding', async () => {
    const nextQuery = 'z=last&pageAfter=a%2Fb%3D&repeat=1&repeat=2&reserved=%2B%26,still-opaque'
    const previousQuery = 'pageBefore=before%2Fvalue&pageSize=2'
    const transport = new SequenceTransport([
      response({
        link:
          `<${ORIGIN}/v1/accounts?${nextQuery}>; rel="NeXt", ` +
          `<${ORIGIN}/v1/accounts?${previousQuery}>; rel="prev"`,
      }),
      response(),
      response(),
    ])
    const page = await createDaaUserClient(transport, 'production', NO_SIGNING).accounts.list()

    await page.next()
    await page.previous()

    expect(transport.sent[1]?.query).toBe(nextQuery)
    expect(transport.sent[2]?.query).toBe(previousQuery)
    for (const request of transport.sent) {
      expect(request.path).toBe('/v1/accounts')
      expect(request.method).toBe('GET')
      expect(request.headers).toEqual({})
      expect(request.bodyBytes).toBeNull()
    }
  })

  it('preserves the distinction between an absent and explicitly empty query', async () => {
    for (const [target, expected] of [
      [`${ORIGIN}/v1/accounts`, null],
      [`${ORIGIN}/v1/accounts?`, ''],
    ] as const) {
      const transport = new SequenceTransport([
        response({ Link: `<${target}>; rel="next"` }),
        response(),
      ])
      const page = await createDaaUserClient(transport, 'production', NO_SIGNING).accounts.list()
      await page.next()
      expect(transport.sent[1]?.query).toBe(expected)
    }
  })

  it('compares origins by HTTPS host and effective port rather than textual casing', async () => {
    const transport = new SequenceTransport([
      response({ Link: '<HTTPS://API.CIRCLE.COM:443/v1/accounts?pageAfter=x>; rel="next"' }),
      response(),
    ])
    const page = await createDaaUserClient(transport, 'production', NO_SIGNING).accounts.list()
    await page.next()

    expect(transport.sent[1]?.query).toBe('pageAfter=x')
  })

  it('keeps the pagination trust decision independent of the host URL implementation', async () => {
    const originalUrl = globalThis.URL
    Object.defineProperty(globalThis, 'URL', {
      configurable: true,
      value: undefined,
      writable: true,
    })
    try {
      const transport = new SequenceTransport([
        response({ Link: `<${ORIGIN}/v1/accounts?pageAfter=x>; rel="next"` }),
        response(),
      ])
      const page = await createDaaUserClient(transport, 'production', NO_SIGNING).accounts.list()

      await expect(page.next()).resolves.not.toBeNull()
      expect(transport.sent[1]?.query).toBe('pageAfter=x')
    } finally {
      Object.defineProperty(globalThis, 'URL', {
        configurable: true,
        value: originalUrl,
        writable: true,
      })
    }
  })

  it('uses the selected environment as the pagination trust anchor', async () => {
    const transport = new SequenceTransport([
      response({ Link: `<${ORIGIN}/v1/accounts?pageAfter=x>; rel="next"` }),
    ])

    const detail = await detailOf(
      createDaaUserClient(transport, 'sandbox', NO_SIGNING).accounts.list(),
    )

    expect(detail.kind).toBe('contract_violation')
    expect(transport.sent).toHaveLength(1)
  })

  it('uses publicApiOrigin, not the environment origin, as the trust anchor when set', async () => {
    const override = 'https://api-test.circle.com'
    const trusted = new SequenceTransport([
      response({ Link: `<${override}/v1/accounts?pageAfter=x>; rel="next"` }),
      response(),
    ])
    const page = await createDaaUserClient(trusted, 'sandbox', NO_SIGNING, override).accounts.list()
    await page.next()
    expect(trusted.sent[1]?.query).toBe('pageAfter=x')

    const untrusted = new SequenceTransport([
      response({ Link: '<https://api-sandbox.circle.com/v1/accounts?pageAfter=x>; rel="next"' }),
    ])
    const detail = await detailOf(
      createDaaUserClient(untrusted, 'sandbox', NO_SIGNING, override).accounts.list(),
    )
    expect(detail.kind).toBe('contract_violation')
    expect(untrusted.sent).toHaveLength(1)
  })

  it.each([
    'http://api.circle.com/v1/accounts?pageAfter=x',
    'https://evil.example/v1/accounts?pageAfter=x',
    'https://api.circle.com.evil.example/v1/accounts?pageAfter=x',
    'https://api.circle.com:444/v1/accounts?pageAfter=x',
    'https://user@api.circle.com/v1/accounts?pageAfter=x',
    'https://api.circle.com/v1/accounts?pageAfter=x#fragment',
    'https://api.circle.com/v1/accounts/transfers?pageAfter=x',
    'https://api.circle.com/v10/accounts?pageAfter=x',
    'https://api.circle.com/v1/accounts/../withdrawals?pageAfter=x',
    'https://api.circle.com/v1//accounts?pageAfter=x',
    'https://api.circle.com/v1/%61ccounts?pageAfter=x',
    'https://api.circle.com/v1/accounts?pageAfter=%zz',
    'https://api.circle.com/v1/accounts?pageAfter=a b',
    'https://api.circle.com/v1/accounts?pageAfter="quoted"',
    'https://api.circle.com/v1/accounts?pageAfter=raw-\u{1f4a9}',
    '/v1/accounts?pageAfter=x',
    '//api.circle.com/v1/accounts?pageAfter=x',
    ' https://api.circle.com/v1/accounts?pageAfter=x',
    'https://api.circle.com\\v1\\accounts?pageAfter=x',
  ])('rejects an untrusted target without following it: %s', async (target) => {
    const transport = new SequenceTransport([response({ Link: `<${target}>; rel="next"` })])
    const detail = await detailOf(
      createDaaUserClient(transport, 'production', NO_SIGNING).accounts.list(),
    )

    expect(detail.kind).toBe('contract_violation')
    expect(transport.sent).toHaveLength(1)
  })

  it.each([
    {
      Link: `<${ORIGIN}/v1/accounts?pageAfter=1>; rel="next", <${ORIGIN}/v1/accounts?pageAfter=2>; rel="NEXT"`,
    },
    {
      Link: `<${ORIGIN}/v1/accounts?pageAfter=1>; rel="next"; rel="prev"`,
    },
    {
      Link: `<${ORIGIN}/v1/accounts?pageAfter=1>; rel="next prev"`,
    },
    {
      Link: `<${ORIGIN}/v1/accounts?pageAfter=1>; rel=next`,
    },
    {
      Link: `<${ORIGIN}/v1/accounts?pageAfter=1>; rel="next"; title="unused"`,
    },
    {
      Link: `<${ORIGIN}/v1/accounts?pageAfter=1; rel="next"`,
    },
    {
      Link: `<${ORIGIN}/v1/accounts?pageAfter=1>; rel`,
    },
    {
      Link: `<${ORIGIN}/v1/accounts?pageAfter=1>; rel=""`,
    },
    {
      Link: `<${ORIGIN}/v1/accounts?pageAfter=1>; rel="next", `,
    },
    {
      Link: `<${ORIGIN}/v1/accounts?pageAfter=1>; rel="next"`,
      link: `<${ORIGIN}/v1/accounts?pageAfter=2>; rel="prev"`,
    },
  ])('rejects malformed, unsupported, or ambiguous Link metadata', async (headers) => {
    const transport = new SequenceTransport([
      response({ ...headers, 'X-Request-Id': 'req-pagination' }),
    ])
    const detail = await detailOf(
      createDaaUserClient(transport, 'production', NO_SIGNING).accounts.list(),
    )

    expect(detail).toEqual({ kind: 'contract_violation', correlationId: 'req-pagination' })
    expect(transport.sent).toHaveLength(1)
  })

  it('ignores unrelated link relations', async () => {
    const transport = new SequenceTransport([
      response({ Link: `<https://evil.example/not-used>; rel="alternate"` }),
    ])
    const page = await createDaaUserClient(transport, 'production', NO_SIGNING).accounts.list()

    await expect(page.next()).resolves.toBeNull()
    await expect(page.previous()).resolves.toBeNull()
  })

  it.each([
    { pageAfter: 'one', pageBefore: 'two' },
    { pageSize: 0 },
    { pageSize: 1.5 },
    { clientEntityId: 'not-a-uuid' },
    { custodyType: 'unknown' },
    { status: ['unknown'] },
    { currencies: [''] },
    { from: '' },
  ])('rejects an invalid initial query without sending it: %o', async (query) => {
    const transport = new SequenceTransport([])
    const accounts = createDaaUserClient(transport, 'production', NO_SIGNING).accounts
    const detail = await detailOf(accounts.list(query as never))

    expect(detail.kind).toBe('contract_violation')
    expect(transport.sent).toHaveLength(0)
  })

  it('maps malformed list bodies and unexpected success statuses through the shared response rules', async () => {
    const malformed = new SequenceTransport([
      { status: 200, headers: { 'X-Request-Id': 'req-list' }, bodyBytes: bytes('{"data":{}}') },
    ])
    await expect(
      detailOf(createDaaUserClient(malformed, 'production', NO_SIGNING).accounts.list()),
    ).resolves.toEqual({ kind: 'contract_violation', correlationId: 'req-list' })

    const wrongStatus = new SequenceTransport([{ status: 201, headers: {}, bodyBytes: pageBody() }])
    await expect(
      detailOf(createDaaUserClient(wrongStatus, 'production', NO_SIGNING).accounts.list()),
    ).resolves.toMatchObject({ kind: 'api', httpStatus: 201 })
  })
})
