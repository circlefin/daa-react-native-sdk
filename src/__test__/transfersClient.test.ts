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
import type { TransfersClient } from '../api/TransfersClient'
import { isDaaError } from '../errors'
import type { DaaSdkError } from '../errors'
import type { DaaHttpRequest, DaaHttpResponse, DaaTransport } from '../transport/DaaTransport'

/**
 * The transfer read, end to end through the client: request shape, envelope,
 * decoding, and status mapping. Mirrors `accountsClient.test.ts`'s structure —
 * same client shape, same envelope, same error mapping, different model.
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
const TRANSFER_ID = '7c2d9e10-3b4f-4a52-9d6e-0f1a2b3c4d5e'

/** A complete transfer: every field the service guarantees. */
const COMPLETE_TRANSFER =
  '{"id":"tr-1","source":{"type":"account","id":"acct-src"},' +
  '"destination":{"type":"account","id":"acct-dst"},' +
  '"amount":{"amount":"10.00","currency":"USD"},"status":"pending"}'

function bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text)
}

function envelope(payload: string): Uint8Array {
  return bytes(`{"data":${payload}}`)
}

function clientFor(response: Partial<DaaHttpResponse>): {
  transfers: TransfersClient
  transport: RecordingTransport
} {
  const transport = new RecordingTransport({
    status: response.status ?? 200,
    headers: response.headers ?? {},
    bodyBytes: response.bodyBytes ?? null,
  })
  return {
    transfers: createDaaUserClient(transport, 'production', NO_SIGNING).transfers,
    transport,
  }
}

function okClient(payload = COMPLETE_TRANSFER) {
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
  it('reads a transfer over the transfers path', async () => {
    const { transfers, transport } = okClient()

    const transfer = await transfers.get(TRANSFER_ID)

    expect(transport.sent).toHaveLength(1)
    const sent = transport.sent[0] as DaaHttpRequest
    expect(sent.method).toBe('GET')
    expect(sent.path).toBe(`/v1/accounts/transfers/${TRANSFER_ID}`)
    expect(sent.query).toBeNull()
    expect(sent.bodyBytes).toBeNull()
    expect(sent.headers).toEqual({})
    expect(transfer.id).toBe('tr-1')
    expect(transfer.status).toEqual({ kind: 'pending' })
  })

  /**
   * A `transferId` carrying a path separator would address a different
   * operation rather than fail. An empty one addresses the collection instead
   * of a member.
   */
  it('rejects a transferId that would address a different route', async () => {
    const { transfers, transport } = okClient()

    for (const bad of [`${TRANSFER_ID}/other`, `${TRANSFER_ID}/`, `/${TRANSFER_ID}`, '', 'a/b/c']) {
      const detail = await detailOf(transfers.get(bad))
      expect(detail.kind).toBe('contract_violation')
    }
    expect(transport.sent).toHaveLength(0)
  })

  it('rejects a transferId carrying an encoded separator or other unsafe character', async () => {
    const { transfers, transport } = okClient()

    for (const bad of [
      `${TRANSFER_ID}%2Fother`,
      'tr%2f1',
      `${TRANSFER_ID}?x=1`,
      `${TRANSFER_ID}#frag`,
      `${TRANSFER_ID} `,
      // Written as an escape, not a literal byte: a literal NUL makes git treat
      // the file as binary.
      `${TRANSFER_ID}\u0000`,
      `${TRANSFER_ID}\r\nX-Injected: 1`,
      '.',
      '..',
      'tr/../other',
    ]) {
      const detail = await detailOf(transfers.get(bad))
      expect(detail.kind).toBe('contract_violation')
    }
    expect(transport.sent).toHaveLength(0)
  })

  it('accepts a UUID-formatted id in either case', async () => {
    for (const good of [TRANSFER_ID, TRANSFER_ID.toUpperCase()]) {
      const { transfers, transport } = okClient()
      await transfers.get(good)
      expect(transport.sent[0]?.path).toBe(`/v1/accounts/transfers/${good}`)
    }
  })

  /**
   * The SDK contract types this parameter `transferId: UUID`, unlike
   * `accounts.get`, whose id is a `string` because public account ids may be
   * numeric. An id that would pass a generic path-segment guard is still
   * rejected here: it cannot resolve to a transfer, so sending it would only
   * turn a caller's mistake into a round trip and a `400`. The near-miss UUIDs
   * are the cases a loose check waves through.
   */
  it('rejects an id that is well-formed as a path segment but is not a UUID', async () => {
    const { transfers, transport } = okClient()

    for (const bad of [
      'tr-1',
      'TR_1',
      'a.b~c',
      '0123456789',
      '7c2d9e103b4f4a529d6e0f1a2b3c4d5e',
      '7c2d9e10-3b4f-4a52-9d6e-0f1a2b3c4d5',
      '7c2d9e10-3b4f-4a52-9d6e-0f1a2b3c4d5ef',
      '7g2d9e10-3b4f-4a52-9d6e-0f1a2b3c4d5e',
    ]) {
      expect((await detailOf(transfers.get(bad))).kind).toBe('contract_violation')
    }
    expect(transport.sent).toHaveLength(0)
  })
})

describe('the success path', () => {
  it('accepts the documented 200 success', async () => {
    const { transfers } = clientFor({
      status: 200,
      bodyBytes: envelope(COMPLETE_TRANSFER),
    })
    expect((await transfers.get(TRANSFER_ID)).id).toBe('tr-1')
  })

  /** The payload sits under `data`; a body with it at the root is malformed, not a value-less transfer. */
  it('rejects a body whose transfer sits at the root instead of the envelope', async () => {
    const { transfers } = clientFor({
      status: 200,
      headers: { 'X-Request-Id': 'req-2' },
      bodyBytes: bytes(COMPLETE_TRANSFER),
    })

    expect(await detailOf(transfers.get(TRANSFER_ID))).toEqual({
      kind: 'contract_violation',
      correlationId: 'req-2',
    })
  })

  /** An envelope present but empty is malformed — the wrapper is not optional on a 200. */
  it('rejects an empty envelope, an empty body, and no body at all', async () => {
    for (const bodyBytes of [bytes('{"data":null}'), bytes(''), null]) {
      const { transfers } = clientFor({ status: 200, bodyBytes })
      expect((await detailOf(transfers.get(TRANSFER_ID))).kind).toBe('contract_violation')
    }
  })

  /**
   * A `200` whose transfer is missing something the service guarantees must
   * reach the caller as a broken contract, not as a successful transfer with
   * holes in it. The correlation id has to survive.
   */
  it('reports a transfer missing guaranteed fields as a broken contract with the correlation id', async () => {
    const payloads = [
      '{}',
      '{"id":"tr-1"}',
      '{"id":"tr-1","source":{"type":"account","id":"a"},"status":"pending"}',
      // A guaranteed money amount the SDK cannot read is the same defect.
      '{"id":"tr-1","source":{"type":"account","id":"a"},' +
        '"destination":{"type":"account","id":"b"},' +
        '"amount":{"amount":"nope","currency":"USD"},"status":"pending"}',
    ]

    for (const payload of payloads) {
      const { transfers } = clientFor({
        status: 200,
        headers: { 'X-Request-Id': 'req-13' },
        bodyBytes: envelope(payload),
      })
      expect(await detailOf(transfers.get(TRANSFER_ID))).toEqual({
        kind: 'contract_violation',
        correlationId: 'req-13',
      })
    }
  })

  it('treats a non-integer status as a failure rather than a success', async () => {
    for (const status of [Number.NaN, 200.5, Number.POSITIVE_INFINITY]) {
      const { transfers } = clientFor({
        status: status as number,
        bodyBytes: envelope(COMPLETE_TRANSFER),
      })

      const detail = await detailOf(transfers.get(TRANSFER_ID))
      expect(detail.kind).toBe('api')
    }
  })

  /** No field name from the response reaches the error a consumer sees. */
  it('does not put a response field name in the error message', async () => {
    const { transfers } = clientFor({ status: 200, bodyBytes: envelope('{"id":"tr-1"}') })

    try {
      await transfers.get(TRANSFER_ID)
      throw new Error('expected the read to fail')
    } catch (err) {
      expect(isDaaError(err)).toBe(true)
      expect((err as Error).message).not.toContain('destination')
      expect((err as Error).message).not.toContain('amount')
    }
  })

  /** A destination on-chain address is the field a caller resolving a transfer needs, and it must decode. */
  it('surfaces a blockchain destination leg and its fees', async () => {
    const { transfers } = okClient(
      '{"id":"tr-1","source":{"type":"account","id":"acct-src"},' +
        '"destination":{"type":"blockchain","chain":"ETH","address":"0xdest","addressTag":null},' +
        '"amount":{"amount":"10.500000","currency":"USD"},"status":"complete",' +
        '"fees":[{"amount":"0.01","currency":"ETH","type":"network"}]}',
    )

    const transfer = await transfers.get(TRANSFER_ID)

    expect(transfer.destination?.kind).toBe('blockchain')
    expect(transfer.status).toEqual({ kind: 'complete' })
    expect(transfer.fees).toHaveLength(1)
    expect(transfer.amount.amount).toBe('10.500000')
  })

  /**
   * A fiat leg is an ordinary onramp/offramp, not a defect: the service reports
   * no leg for it and omits the key, which must decode as `null` rather than a
   * thrown error. A client resolving a real onramp transfer
   * must be able to read it.
   */
  it('surfaces a transfer with a fiat source (an onramp) as a null source', async () => {
    const { transfers } = okClient(
      '{"id":"tr-1","destination":{"type":"account","id":"acct-dst"},' +
        '"amount":{"amount":"100.00","currency":"USD"},"status":"complete"}',
    )

    const transfer = await transfers.get(TRANSFER_ID)

    expect(transfer.source).toBeNull()
    expect(transfer.destination?.kind).toBe('account')
  })
})

describe('the failure path', () => {
  it('maps every status other than 200 onto the api error carrying the status', async () => {
    for (const status of [201, 204, 299, 400, 401, 404, 409, 500, 503]) {
      const { transfers } = clientFor({
        status,
        headers: { 'X-Request-Id': `req-${status}` },
        bodyBytes: bytes(`{"status":{"code":${status * 10},"message":"nope"}}`),
      })

      const detail = await detailOf(transfers.get(TRANSFER_ID))
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
      const { transfers } = clientFor({ status })
      expect(await detailOf(transfers.get(TRANSFER_ID))).toMatchObject({ kind: 'api', retryable })
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
      const { transfers } = clientFor({ status: 502, bodyBytes })
      expect(await detailOf(transfers.get(TRANSFER_ID))).toEqual({
        kind: 'api',
        httpStatus: 502,
        retryable: true,
      })
    }
  })

  it('finds the correlation id whichever casing the transport uses', async () => {
    for (const name of ['X-Request-Id', 'x-request-id', 'X-REQUEST-ID']) {
      const { transfers } = clientFor({ status: 404, headers: { [name]: 'req-9' } })
      try {
        await transfers.get(TRANSFER_ID)
        throw new Error('expected the read to fail')
      } catch (err) {
        expect((err as Error).message).toContain('req-9')
      }
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
      createDaaUserClient(transport, 'production', NO_SIGNING).transfers.get(TRANSFER_ID),
    ).rejects.toMatchObject({
      detail: { kind: 'transport', retryable: true },
      cause: failure,
    })
  })
})

describe('reachability', () => {
  it('is reached through the internal user-client factory', () => {
    const transport: DaaTransport = {
      async send() {
        return { status: 200, headers: {}, bodyBytes: null }
      },
    }
    const client = createDaaUserClient(transport, 'production', NO_SIGNING).transfers
    expect(typeof client.get).toBe('function')
    expect(Object.isFrozen(client)).toBe(true)
  })
})
