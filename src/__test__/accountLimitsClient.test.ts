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
 * The account limits/usage read, end to end through the client: request
 * shape, query serialization, envelope, decoding, and status mapping.
 * Mirrors `accountsClient.test.ts` and `depositsClient.test.ts`.
 *
 * The public API reference
 * (https://developers.circle.com/api-reference/digital-asset-accounts/all/list-account-limits-usage)
 * is the source of truth these tests pin.
 */

class RecordingTransport implements DaaTransport {
  readonly sent: DaaHttpRequest[] = []

  constructor(private readonly response: DaaHttpResponse) {}

  async send(request: DaaHttpRequest): Promise<DaaHttpResponse> {
    this.sent.push(request)
    return this.response
  }
}

const ACCOUNT_ID = '1000662322'

/** A complete transaction-limit item: every field a `comparisonType: transaction` row carries. */
const TRANSACTION_ITEM =
  '{"operation":"withdrawal","assetType":"fiat","comparisonType":"transaction",' +
  '"unit":"usd_cents","effectiveThreshold":5000000}'

/** A complete aggregation-limit item: every field the public reference documents. */
const AGGREGATION_ITEM =
  '{"operation":"send","assetType":"crypto","comparisonType":"aggregation","window":"PT24H",' +
  '"unit":"usd_cents","effectiveThreshold":1000000,"currentAggregate":1234567,"usagePercent":24.69}'

const COMPLETE_LIMITS_USAGE =
  `{"type":"limitsUsage","accountId":"${ACCOUNT_ID}","currency":"USD",` +
  `"watermark":"2026-05-12T10:29:58.000Z","items":[${TRANSACTION_ITEM},${AGGREGATION_ITEM}]}`

function bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text)
}

function envelope(payload: string): Uint8Array {
  return bytes(`{"data":${payload}}`)
}

function clientFor(response: Partial<DaaHttpResponse>): {
  accountLimits: ReturnType<typeof createDaaUserClient>['accountLimits']
  transport: RecordingTransport
} {
  const transport = new RecordingTransport({
    status: response.status ?? 200,
    headers: response.headers ?? {},
    bodyBytes: response.bodyBytes ?? null,
  })
  return {
    accountLimits: createDaaUserClient(transport, 'production', NO_SIGNING).accountLimits,
    transport,
  }
}

function okClient(payload = COMPLETE_LIMITS_USAGE) {
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
  it('reads account limits/usage over the public path with no query by default', async () => {
    const { accountLimits, transport } = okClient()

    const usage = await accountLimits.get(ACCOUNT_ID)

    expect(transport.sent).toHaveLength(1)
    const sent = transport.sent[0] as DaaHttpRequest
    expect(sent.method).toBe('GET')
    expect(sent.path).toBe(`/v1/accounts/${ACCOUNT_ID}/limits/usage`)
    expect(sent.query).toBeNull()
    expect(sent.bodyBytes).toBeNull()
    expect(sent.headers).toEqual({})
    expect(usage.accountId).toBe(ACCOUNT_ID)
    expect(usage.currency).toBe('USD')
  })

  it('accepts every accountId length the documented pattern allows', async () => {
    for (const good of ['1', '12', '1234567890']) {
      const { accountLimits, transport } = okClient()
      await accountLimits.get(good)
      expect(transport.sent[0]?.path).toBe(`/v1/accounts/${good}/limits/usage`)
    }
  })

  /**
   * The public reference documents this path parameter as `^\d{1,10}$` —
   * stricter than `AccountsClient.get`'s broader path-segment guard. An
   * accountId that would address a different route, one with too many
   * digits, or one that is not purely numeric is all rejected locally.
   */
  it('rejects an accountId that does not match the documented numeric pattern', async () => {
    const { accountLimits, transport } = okClient()

    for (const bad of [
      '',
      '01234567890', // 11 digits
      '12345678901', // 11 digits
      'acct-1',
      '1000662322/transfers',
      '1000662322/',
      '/1000662322',
      '1000662322%2Ftransfers',
      '1000662322?x=1',
      '1000662322#frag',
      ' 1000662322',
      '1000662322 ',
      '1000662322\r\nX-Injected: 1',
      '-1',
      '1.0',
      '1e5',
    ]) {
      const detail = await detailOf(accountLimits.get(bad))
      expect(detail.kind).toBe('contract_violation')
    }
    expect(transport.sent).toHaveLength(0)
  })

  describe('query serialization', () => {
    it('sends no query when none is supplied', async () => {
      const { accountLimits, transport } = okClient()
      await accountLimits.get(ACCOUNT_ID)
      expect(transport.sent[0]?.query).toBeNull()
    })

    it('sends no query for an explicitly empty query object', async () => {
      const { accountLimits, transport } = okClient()
      await accountLimits.get(ACCOUNT_ID, {})
      expect(transport.sent[0]?.query).toBeNull()
    })

    it('serializes operation alone', async () => {
      const { accountLimits, transport } = okClient()
      await accountLimits.get(ACCOUNT_ID, { operation: 'fiat_linking' })
      expect(transport.sent[0]?.query).toBe('operation=fiat_linking')
    })

    it('serializes assetType alone', async () => {
      const { accountLimits, transport } = okClient()
      await accountLimits.get(ACCOUNT_ID, { assetType: 'crypto' })
      expect(transport.sent[0]?.query).toBe('assetType=crypto')
    })

    it('serializes window alone', async () => {
      const { accountLimits, transport } = okClient()
      await accountLimits.get(ACCOUNT_ID, { window: 'P30D' })
      expect(transport.sent[0]?.query).toBe('window=P30D')
    })

    it('serializes all three filters together in one deterministic order', async () => {
      const { accountLimits, transport } = okClient()
      await accountLimits.get(ACCOUNT_ID, {
        operation: 'withdrawal',
        assetType: 'fiat',
        window: 'PT24H',
      })
      expect(transport.sent[0]?.query).toBe('operation=withdrawal&assetType=fiat&window=PT24H')
    })

    it('accepts every documented operation value', async () => {
      for (const operation of [
        'deposit',
        'withdrawal',
        'receive',
        'send',
        'send_count',
        'address_linking',
        'fiat_linking',
        'deposit_return_count',
        'balance_cap',
      ] as const) {
        const { accountLimits, transport } = okClient()
        await accountLimits.get(ACCOUNT_ID, { operation })
        expect(transport.sent[0]?.query).toBe(`operation=${operation}`)
      }
    })

    it('accepts both documented window values', async () => {
      for (const window of ['PT24H', 'P30D'] as const) {
        const { accountLimits, transport } = okClient()
        await accountLimits.get(ACCOUNT_ID, { window })
        expect(transport.sent[0]?.query).toBe(`window=${window}`)
      }
    })

    it('rejects an unsupported operation value without sending a request', async () => {
      const { accountLimits, transport } = okClient()
      const detail = await detailOf(
        accountLimits.get(ACCOUNT_ID, {
          operation: 'wire' as unknown as 'deposit',
        }),
      )
      expect(detail.kind).toBe('contract_violation')
      expect(transport.sent).toHaveLength(0)
    })

    it('rejects an unsupported window value without sending a request', async () => {
      const { accountLimits, transport } = okClient()
      const detail = await detailOf(
        accountLimits.get(ACCOUNT_ID, { window: 'P7D' as unknown as 'P30D' }),
      )
      expect(detail.kind).toBe('contract_violation')
      expect(transport.sent).toHaveLength(0)
    })

    /**
     * The API rejects `window=PT24H` combined with
     * `operation=fiat_linking`/`deposit_return_count` server-side (a `400`).
     * This SDK does not pre-validate that combination locally — see
     * `AccountLimitsClient`'s class note — so the request still goes out and
     * the service's rejection surfaces as an ordinary `api` failure.
     */
    it('does not pre-validate the window=PT24H + fiat_linking/deposit_return_count combination', async () => {
      for (const operation of ['fiat_linking', 'deposit_return_count'] as const) {
        const { accountLimits, transport } = okClient()
        await accountLimits.get(ACCOUNT_ID, { operation, window: 'PT24H' })
        expect(transport.sent[0]?.query).toBe(`operation=${operation}&window=PT24H`)
      }
    })

    it('rejects a non-object query', async () => {
      const { accountLimits, transport } = okClient()
      const detail = await detailOf(accountLimits.get(ACCOUNT_ID, null as unknown as undefined))
      expect(detail.kind).toBe('contract_violation')
      expect(transport.sent).toHaveLength(0)
    })
  })
})

describe('the success path', () => {
  it('rejects undocumented 2xx statuses as API failures', async () => {
    for (const status of [201, 204, 299]) {
      const { accountLimits } = clientFor({ status, bodyBytes: envelope(COMPLETE_LIMITS_USAGE) })
      expect(await detailOf(accountLimits.get(ACCOUNT_ID))).toMatchObject({
        kind: 'api',
        httpStatus: status,
      })
    }
  })

  it('rejects a body whose payload sits at the root instead of the envelope', async () => {
    const { accountLimits } = clientFor({
      status: 200,
      headers: { 'X-Request-Id': 'req-2' },
      bodyBytes: bytes(COMPLETE_LIMITS_USAGE),
    })

    expect(await detailOf(accountLimits.get(ACCOUNT_ID))).toEqual({
      kind: 'contract_violation',
      correlationId: 'req-2',
    })
  })

  it('rejects an empty envelope, an empty body, and no body at all', async () => {
    for (const bodyBytes of [bytes('{"data":null}'), bytes(''), null]) {
      const { accountLimits } = clientFor({ status: 200, bodyBytes })
      expect((await detailOf(accountLimits.get(ACCOUNT_ID))).kind).toBe('contract_violation')
    }
  })

  it('reports a response missing guaranteed fields as a broken contract with the correlation id', async () => {
    const payloads = [
      '{}',
      `{"type":"limitsUsage","accountId":"${ACCOUNT_ID}"}`,
      `{"type":"limitsUsage","accountId":"${ACCOUNT_ID}","currency":"USD"}`,
      `{"type":"limitsUsage","accountId":"${ACCOUNT_ID}","currency":"USD",` +
        `"watermark":"2026-05-12T10:29:58.000Z"}`,
    ]

    for (const payload of payloads) {
      const { accountLimits } = clientFor({
        status: 200,
        headers: { 'X-Request-Id': 'req-13' },
        bodyBytes: envelope(payload),
      })
      expect(await detailOf(accountLimits.get(ACCOUNT_ID))).toEqual({
        kind: 'contract_violation',
        correlationId: 'req-13',
      })
    }
  })
})

describe('the failure path', () => {
  it('maps a status other than 200 onto the api error carrying the status', async () => {
    for (const status of [400, 401, 404, 409, 500, 503]) {
      const { accountLimits } = clientFor({
        status,
        headers: { 'X-Request-Id': `req-${status}` },
        bodyBytes: bytes(`{"status":{"code":${status * 10},"message":"nope"}}`),
      })

      const detail = await detailOf(accountLimits.get(ACCOUNT_ID))
      expect(detail).toEqual({
        kind: 'api',
        httpStatus: status,
        daaStatusCode: status * 10,
        retryable: status === 429 || status >= 500,
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
      createDaaUserClient(transport, 'production', NO_SIGNING).accountLimits.get(ACCOUNT_ID),
    ).rejects.toMatchObject({
      detail: { kind: 'transport', retryable: true },
      cause: failure,
    })
  })
})

describe('reachability', () => {
  it('is reached only through the internal user-client factory', () => {
    const transport: DaaTransport = {
      async send() {
        return { status: 200, headers: {}, bodyBytes: null }
      },
    }
    const user = createDaaUserClient(transport, 'production', NO_SIGNING)
    expect(typeof user.accountLimits.get).toBe('function')
    expect(Object.isFrozen(user)).toBe(true)
    expect(Object.isFrozen(user.accountLimits)).toBe(true)
  })
})
