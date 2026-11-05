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
import { DEPOSIT_TYPES } from '../api/DepositsClient'
import type { DepositsClient } from '../api/DepositsClient'
import { isDaaError } from '../errors'
import type { DaaSdkError } from '../errors'
import type { Money } from '../models/Money'
import type { DaaHttpRequest, DaaHttpResponse, DaaTransport } from '../transport/DaaTransport'

/**
 * The deposit read, end to end through the client: request shape, envelope,
 * decoding, and status mapping. Mirrors `accountsClient.test.ts`.
 * The client is reached through the internal user-client factory, the same
 * path `DaaClient.forUser` uses.
 */

class RecordingTransport implements DaaTransport {
  readonly sent: DaaHttpRequest[] = []

  constructor(private readonly response: DaaHttpResponse) {}

  async send(request: DaaHttpRequest): Promise<DaaHttpResponse> {
    this.sent.push(request)
    return this.response
  }
}

/** The service types this path parameter as a UUID, so every read uses one. */
const DEPOSIT_ID = '3f1a2b4c-5d6e-4f70-8192-a3b4c5d6e7f8'

/** A complete deposit: every field the service guarantees. */
const COMPLETE_DEPOSIT =
  '{"id":"dep-1","amount":{"amount":"10.00","currency":"USD"},"status":"pending",' +
  '"createDate":"2026-01-01T00:00:00Z"}'

function bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text)
}

function envelope(payload: string): Uint8Array {
  return bytes(`{"data":${payload}}`)
}

function clientFor(response: Partial<DaaHttpResponse>): {
  deposits: DepositsClient
  transport: RecordingTransport
} {
  const transport = new RecordingTransport({
    status: response.status ?? 200,
    headers: response.headers ?? {},
    bodyBytes: response.bodyBytes ?? null,
  })
  return { deposits: createDaaUserClient(transport, 'production', NO_SIGNING).deposits, transport }
}

function okClient(payload = COMPLETE_DEPOSIT) {
  return clientFor({
    status: 200,
    headers: { 'X-Request-Id': 'req-1' },
    bodyBytes: envelope(payload),
  })
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

describe('the request', () => {
  /**
   * Author-time autocomplete/typo-protection union, mirrored from the
   * API's deposit `type` values — not a runtime allowlist. See
   * `DepositsClient.ts`'s `DEPOSIT_TYPES` doc for why the `type` query filter
   * accepts any non-empty string at runtime instead.
   */
  it('mirrors the server DepositType rails exhaustively', () => {
    expect(DEPOSIT_TYPES).toEqual([
      'wire',
      'ach',
      'cbit',
      'rtgs',
      'rtp',
      'xpay',
      'signet',
      'sepa',
      'sepa_instant',
      'sen',
      'pix',
      'cubix',
      'book_transfer',
      'fed_now',
    ])
    expect(Object.isFrozen(DEPOSIT_TYPES)).toBe(true)
  })

  it('reads a deposit over the public deposits path', async () => {
    const { deposits, transport } = okClient()

    const deposit = await deposits.get(DEPOSIT_ID)

    expect(transport.sent).toHaveLength(1)
    const sent = transport.sent[0] as DaaHttpRequest
    expect(sent.method).toBe('GET')
    // The public spelling.
    expect(sent.path).toBe(`/v1/accounts/deposits/${DEPOSIT_ID}`)
    expect(sent.query).toBeNull()
    expect(sent.bodyBytes).toBeNull()
    expect(sent.headers).toEqual({})
    expect(deposit.id).toBe('dep-1')
    expect(deposit.status).toEqual({ kind: 'pending' })
  })

  it('rejects a depositId that would address a different route', async () => {
    const { deposits, transport } = okClient()

    for (const bad of [
      `${DEPOSIT_ID}/transfers`,
      `${DEPOSIT_ID}/`,
      `/${DEPOSIT_ID}`,
      '',
      'a/b/c',
    ]) {
      const detail = await detailOf(deposits.get(bad))
      expect(detail.kind).toBe('contract_violation')
    }
    expect(transport.sent).toHaveLength(0)
  })

  it('rejects a depositId carrying an encoded separator or other unsafe character', async () => {
    const { deposits, transport } = okClient()

    for (const bad of [
      `${DEPOSIT_ID}%2Ftransfers`,
      'dep%2f1',
      `${DEPOSIT_ID}?x=1`,
      `${DEPOSIT_ID}#frag`,
      `${DEPOSIT_ID} `,
      ` ${DEPOSIT_ID}`,
      `${DEPOSIT_ID}\r\nX-Injected: 1`,
      '.',
      '..',
      'dep/../transfers',
    ]) {
      const detail = await detailOf(deposits.get(bad))
      expect(detail.kind).toBe('contract_violation')
    }
    expect(transport.sent).toHaveLength(0)
  })

  it('accepts a UUID-formatted identifier in either case', async () => {
    for (const good of [DEPOSIT_ID, DEPOSIT_ID.toUpperCase()]) {
      const { deposits, transport } = okClient()
      await deposits.get(good)
      expect(transport.sent[0]?.path).toBe(`/v1/accounts/deposits/${good}`)
    }
  })

  /**
   * The SDK contract types this parameter `depositId: UUID`, unlike
   * `accounts.get`, whose id is a `string` because public account ids may be
   * numeric. An id that would pass a generic path-segment guard is still
   * rejected here: it cannot resolve to a deposit, so sending it would only
   * turn a caller's mistake into a round trip and a 400.
   */
  it('rejects an id that is well-formed as a path segment but is not a UUID', async () => {
    const { deposits, transport } = okClient()

    for (const bad of [
      'dep-1',
      'DEP_1',
      'a.b~c',
      '0123456789',
      '3f1a2b4c5d6e4f708192a3b4c5d6e7f8',
      '3f1a2b4c-5d6e-4f70-8192-a3b4c5d6e7f',
      '3f1a2b4c-5d6e-4f70-8192-a3b4c5d6e7f89',
      '3g1a2b4c-5d6e-4f70-8192-a3b4c5d6e7f8',
    ]) {
      expect((await detailOf(deposits.get(bad))).kind).toBe('contract_violation')
    }
    expect(transport.sent).toHaveLength(0)
  })
})

describe('the success path', () => {
  it('rejects undocumented 2xx statuses as API failures', async () => {
    for (const status of [201, 204, 299]) {
      const { deposits } = clientFor({
        status,
        bodyBytes: envelope(COMPLETE_DEPOSIT),
      })
      expect(await detailOf(deposits.get(DEPOSIT_ID))).toMatchObject({
        kind: 'api',
        httpStatus: status,
      })
    }
  })

  it('rejects a body whose deposit sits at the root instead of the envelope', async () => {
    const { deposits } = clientFor({
      status: 200,
      headers: { 'X-Request-Id': 'req-2' },
      bodyBytes: bytes(COMPLETE_DEPOSIT),
    })

    expect(await detailOf(deposits.get(DEPOSIT_ID))).toEqual({
      kind: 'contract_violation',
      correlationId: 'req-2',
    })
  })

  it('rejects a body wrapped in a response key instead of data', async () => {
    const { deposits } = clientFor({
      status: 200,
      bodyBytes: bytes(`{"response":${COMPLETE_DEPOSIT}}`),
    })

    expect((await detailOf(deposits.get(DEPOSIT_ID))).kind).toBe('contract_violation')
  })

  it('rejects an empty envelope, an empty body, and no body at all', async () => {
    for (const bodyBytes of [bytes('{"data":null}'), bytes(''), null]) {
      const { deposits } = clientFor({ status: 200, bodyBytes })
      expect((await detailOf(deposits.get(DEPOSIT_ID))).kind).toBe('contract_violation')
    }
  })

  it('reports a deposit missing guaranteed fields as a broken contract with the correlation id', async () => {
    const payloads = [
      '{}',
      '{"id":"dep-1"}',
      '{"id":"dep-1","amount":{"amount":"10.00","currency":"USD"}}',
      '{"id":"dep-1","amount":{"amount":"nope","currency":"USD"},"status":"pending",' +
        '"createDate":"2026-01-01T00:00:00Z"}',
    ]

    for (const payload of payloads) {
      const { deposits } = clientFor({
        status: 200,
        headers: { 'X-Request-Id': 'req-13' },
        bodyBytes: envelope(payload),
      })
      expect(await detailOf(deposits.get(DEPOSIT_ID))).toEqual({
        kind: 'contract_violation',
        correlationId: 'req-13',
      })
    }
  })

  it('treats a non-integer status as a failure rather than a success', async () => {
    for (const status of [Number.NaN, 200.5, Number.POSITIVE_INFINITY]) {
      const { deposits } = clientFor({
        status: status as number,
        bodyBytes: envelope(COMPLETE_DEPOSIT),
      })

      const detail = await detailOf(deposits.get(DEPOSIT_ID))
      expect(detail.kind).toBe('api')
    }
  })

  /**
   * `destination` can legitimately be absent even on a `200` — see the `Deposit`
   * class note — but when present it must decode.
   */
  it('surfaces a destination when the service includes one', async () => {
    const { deposits } = okClient(
      '{"id":"dep-1","amount":{"amount":"10.00","currency":"USD"},"status":"complete",' +
        '"createDate":"2026-01-01T00:00:00Z","destination":{"type":"account","id":"acct-9"}}',
    )

    const deposit = await deposits.get(DEPOSIT_ID)
    expect(deposit.destination).toEqual({ kind: 'account', accountId: 'acct-9' })
    expect((deposit.amount as Money).amount).toBe('10.00')
  })
})

describe('the failure path', () => {
  it('maps a status other than 200 onto the api error carrying the status', async () => {
    for (const status of [400, 401, 404, 409, 500, 503]) {
      const { deposits } = clientFor({
        status,
        headers: { 'X-Request-Id': `req-${status}` },
        bodyBytes: bytes(`{"status":{"code":${status * 10},"message":"nope"}}`),
      })

      const detail = await detailOf(deposits.get(DEPOSIT_ID))
      expect(detail).toEqual({
        kind: 'api',
        httpStatus: status,
        daaStatusCode: status * 10,
        retryable: status === 429 || status >= 500,
      })
    }
  })

  it('marks only 429 and 5xx retryable', async () => {
    for (const [status, retryable] of [
      [400, false],
      [404, false],
      [428, false],
      [429, true],
      [499, false],
      [500, true],
      [599, true],
    ] as const) {
      const { deposits } = clientFor({ status })
      expect(await detailOf(deposits.get(DEPOSIT_ID))).toMatchObject({ kind: 'api', retryable })
    }
  })

  it('reports the api error even when the body carries no readable status code', async () => {
    for (const bodyBytes of [
      null,
      bytes(''),
      bytes('<html>gateway timeout</html>'),
      bytes('{}'),
      bytes('{"status":{}}'),
    ]) {
      const { deposits } = clientFor({ status: 502, bodyBytes })
      expect(await detailOf(deposits.get(DEPOSIT_ID))).toEqual({
        kind: 'api',
        httpStatus: 502,
        retryable: true,
      })
    }
  })

  it('reports a consumer transport failure as a transport error with it as the cause', async () => {
    const failure = new Error('dns')
    const transport: DaaTransport = {
      async send() {
        throw failure
      },
    }

    await expect(
      createDaaUserClient(transport, 'production', NO_SIGNING).deposits.get(DEPOSIT_ID),
    ).rejects.toMatchObject({
      detail: { kind: 'transport', retryable: true },
      cause: failure,
    })
  })
})
