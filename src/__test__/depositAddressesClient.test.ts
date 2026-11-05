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
import type { DepositAddressesClient } from '../api/DepositAddressesClient'
import { isDaaError } from '../errors'
import type { DaaSdkError } from '../errors'
import { DEPOSIT_ADDRESS_CHAINS } from '../models/GenerateAddressRequest'
import type { DepositAddressChain, GenerateAddressRequest } from '../models/GenerateAddressRequest'
import type { DaaHttpRequest, DaaHttpResponse, DaaTransport } from '../transport/DaaTransport'

/**
 * The deposit-address read, end to end through the client: request shape,
 * envelope, decoding, and status mapping. Mirrors `accountsClient.test.ts`'s
 * structure for the sibling read.
 */

class RecordingTransport implements DaaTransport {
  readonly sent: DaaHttpRequest[] = []

  constructor(private readonly response: DaaHttpResponse) {}

  async send(request: DaaHttpRequest): Promise<DaaHttpResponse> {
    this.sent.push(request)
    return this.response
  }
}

const VALID_ID = '8f3c1e2a-4b5d-4e6f-9a0b-1c2d3e4f5a6b'
const IDEMPOTENCY_KEY = '22222222-2222-4222-a222-222222222222'

/** A complete address: every field every custody source guarantees on a by-id read. */
const COMPLETE_ADDRESS = `{"id":"${VALID_ID}","address":"0xRECEIVE","chain":"ETH"}`
const NEXT_ID = '9f3c1e2a-4b5d-4e6f-9a0b-1c2d3e4f5a6b'

function bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text)
}

function envelope(payload: string): Uint8Array {
  return bytes(`{"data":${payload}}`)
}

function clientFor(response: Partial<DaaHttpResponse>): {
  client: DepositAddressesClient
  transport: RecordingTransport
} {
  const transport = new RecordingTransport({
    status: response.status ?? 200,
    headers: response.headers ?? {},
    bodyBytes: response.bodyBytes ?? null,
  })
  return {
    client: createDaaUserClient(transport, 'production', NO_SIGNING).depositAddresses,
    transport,
  }
}

function okClient(payload = COMPLETE_ADDRESS) {
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
  it('lists addresses over the public collection path and serializes documented filters', async () => {
    const { client, transport } = clientFor({ bodyBytes: envelope(`[${COMPLETE_ADDRESS}]`) })

    const page = await client.list({
      custodyType: 'omnibus',
      accountId: '1000662322',
      chain: 'ETH',
      currency: 'USD',
      from: '2026-01-01T00:00:00Z',
      to: '2026-01-31T23:59:59Z',
      pageAfter: VALID_ID,
      pageSize: 50,
    })

    expect(transport.sent).toHaveLength(1)
    expect(transport.sent[0]).toMatchObject({
      method: 'GET',
      path: '/v1/accounts/addresses/deposit',
      query:
        'custodyType=omnibus&accountId=1000662322&chain=ETH&currency=USD&from=2026-01-01T00%3A00%3A00Z&to=2026-01-31T23%3A59%3A59Z&pageAfter=' +
        `${VALID_ID}&pageSize=50`,
      headers: {},
      bodyBytes: null,
    })
    expect(page.items).toHaveLength(1)
    expect(page.items[0]?.address).toBe('0xRECEIVE')
    expect(Object.isFrozen(page.items)).toBe(true)
  })

  it('replays the API pagination query byte-for-byte on the same deposit-address collection', async () => {
    const first = envelope(`[${COMPLETE_ADDRESS}]`)
    const second = envelope('[]')
    const transport: DaaTransport & { readonly sent: DaaHttpRequest[] } = {
      sent: [],
      async send(request) {
        this.sent.push(request)
        return this.sent.length === 1
          ? {
              status: 200,
              headers: {
                Link: `<https://api.circle.com/v1/accounts/addresses/deposit?pageAfter=${NEXT_ID}%2Bopaque&filter=a%2Fb>; rel="next"`,
              },
              bodyBytes: first,
            }
          : { status: 200, headers: {}, bodyBytes: second }
      },
    }
    const client = createDaaUserClient(transport, 'production', NO_SIGNING).depositAddresses

    const page = await client.list()
    await page.next()

    expect(transport.sent).toHaveLength(2)
    expect(transport.sent[1]).toMatchObject({
      method: 'GET',
      path: '/v1/accounts/addresses/deposit',
      query: `pageAfter=${NEXT_ID}%2Bopaque&filter=a%2Fb`,
    })
  })

  it('closes the unsigned write and retained Page navigation after the user closes', async () => {
    const transport: DaaTransport & { readonly sent: DaaHttpRequest[] } = {
      sent: [],
      async send(request) {
        this.sent.push(request)
        return {
          status: 200,
          headers: {
            Link: `<https://api.circle.com/v1/accounts/addresses/deposit?pageAfter=${NEXT_ID}>; rel="next"`,
          },
          bodyBytes: envelope(`[${COMPLETE_ADDRESS}]`),
        }
      },
    }
    const user = createDaaUserClient(transport, 'production', NO_SIGNING)
    const page = await user.depositAddresses.list()

    user.close()

    const request: GenerateAddressRequest = {
      idempotencyKey: IDEMPOTENCY_KEY,
      accountId: 'acct-1',
      currency: 'USD',
    }
    expect(await detailOf(user.depositAddresses.create(request))).toEqual({
      kind: 'contract_violation',
    })
    expect(await detailOf(page.next())).toEqual({
      kind: 'contract_violation',
    })
    expect(transport.sent).toHaveLength(1)
  })

  it('rejects invalid collection queries before sending a request', async () => {
    const { client, transport } = okClient()

    for (const query of [
      null,
      [],
      { custodyType: 'wrong' },
      { accountId: '' },
      { pageAfter: VALID_ID, pageBefore: NEXT_ID },
      { pageAfter: 'not-a-uuid' },
      { pageSize: 0 },
    ]) {
      expect((await detailOf(client.list(query as never))).kind).toBe('contract_violation')
    }
    expect(transport.sent).toHaveLength(0)
  })

  it('treats a non-array collection data value as a broken contract', async () => {
    const { client } = clientFor({ bodyBytes: envelope(COMPLETE_ADDRESS) })

    expect((await detailOf(client.list())).kind).toBe('contract_violation')
  })

  it('mirrors the canonical public Accounts Chain values exhaustively', () => {
    expect(DEPOSIT_ADDRESS_CHAINS).toEqual([
      'ALGO',
      'APTOS',
      'ARB',
      'AVAX',
      'BASE',
      'BTC',
      'CELO',
      'CODEX',
      'ETH',
      'HBAR',
      'HYPEREVM',
      'INK',
      'LINEA',
      'NEAR',
      'NOBLE',
      'OP',
      'PAH',
      'PLUME',
      'POLY',
      'SEI',
      'SOL',
      'SONIC',
      'SUI',
      'UNI',
      'WORLDCHAIN',
      'XDC',
      'XLM',
      'XRP',
      'ZKS',
      'ZKSYNC',
    ])
    expect(Object.isFrozen(DEPOSIT_ADDRESS_CHAINS)).toBe(true)
  })

  it('reads a deposit address over the public path', async () => {
    const { client, transport } = okClient()

    const address = await client.get(VALID_ID)

    expect(transport.sent).toHaveLength(1)
    const sent = transport.sent[0] as DaaHttpRequest
    expect(sent.method).toBe('GET')
    // The public spelling.
    expect(sent.path).toBe(`/v1/accounts/addresses/deposit/${VALID_ID}`)
    expect(sent.query).toBeNull()
    expect(sent.bodyBytes).toBeNull()
    expect(sent.headers).toEqual({})
    expect(address.id).toBe(VALID_ID)
    expect(address.chain).toBe('ETH')
  })

  /**
   * The service types `depositId` as a required UUID, so any other
   * shape cannot resolve to an address — reject it locally
   * rather than spend a round trip finding out. A UUID-formatted identifier also
   * contains no path separator or control character, so this doubles as the
   * route-confusion defence `AccountsClient.get`'s character-class check
   * exists for.
   */
  it('rejects a depositId that is not UUID-formatted', async () => {
    const { client, transport } = okClient()

    for (const bad of [
      '',
      'not-a-uuid',
      `${VALID_ID}/transfers`,
      `${VALID_ID}%2f`,
      `${VALID_ID}\r\nX-Injected: 1`,
      VALID_ID.replace(/-/g, ''), // no separators
      VALID_ID.slice(0, -1), // one char short
      `${VALID_ID}0`, // one char long
      '.',
      '..',
    ]) {
      const detail = await detailOf(client.get(bad))
      expect(detail.kind).toBe('contract_violation')
    }
    expect(transport.sent).toHaveLength(0)
  })

  it('accepts an uppercase UUID', async () => {
    const { client, transport } = okClient()
    const upper = VALID_ID.toUpperCase()
    await client.get(upper)
    expect(transport.sent[0]?.path).toBe(`/v1/accounts/addresses/deposit/${upper}`)
  })

  it('creates over the public path with the exact documented body bytes', async () => {
    const { client, transport } = clientFor({
      status: 201,
      headers: {
        Location: `/v1/accounts/addresses/deposit/${VALID_ID}`,
        'X-Request-Id': 'req-create',
      },
      bodyBytes: envelope(COMPLETE_ADDRESS),
    })
    const request: GenerateAddressRequest = {
      idempotencyKey: IDEMPOTENCY_KEY,
      accountId: 'account-1',
      currency: 'USD',
      chain: 'ETH',
    }

    const address = await client.create(request)

    expect(transport.sent).toHaveLength(1)
    const sent = transport.sent[0] as DaaHttpRequest
    expect(sent).toMatchObject({
      method: 'POST',
      path: '/v1/accounts/addresses/deposit',
      query: null,
      headers: { 'Content-Type': 'application/json' },
    })
    expect(new TextDecoder().decode(sent.bodyBytes as Uint8Array)).toBe(
      `{"idempotencyKey":"${IDEMPOTENCY_KEY}","accountId":"account-1","currency":"USD","chain":"ETH"}`,
    )
    expect(address.id).toBe(VALID_ID)
    expect(address.address).toBe('0xRECEIVE')
    expect(Object.isFrozen(address)).toBe(true)
    expect(Object.keys(address)).not.toContain('address')
    expect(JSON.stringify(address)).not.toContain('0xRECEIVE')
  })

  it('omits custodyType so DAA derives the authoritative selector from accountId', async () => {
    const { client, transport } = clientFor({
      status: 201,
      bodyBytes: envelope(COMPLETE_ADDRESS),
    })

    await client.create({
      idempotencyKey: IDEMPOTENCY_KEY,
      accountId: 'account-1',
      currency: 'EUR',
      chain: 'SOL',
    })

    const sent = transport.sent[0] as DaaHttpRequest
    expect(sent.query).toBeNull()
    expect(new TextDecoder().decode(sent.bodyBytes as Uint8Array)).not.toContain('custodyType')
  })

  it('snapshots each field once and drops properties outside the wire contract', async () => {
    const { client, transport } = clientFor({
      status: 201,
      bodyBytes: envelope(COMPLETE_ADDRESS),
    })
    const reads = { idempotencyKey: 0, accountId: 0, currency: 0, chain: 0 }
    const request = {
      get idempotencyKey() {
        reads.idempotencyKey += 1
        return IDEMPOTENCY_KEY
      },
      get accountId() {
        reads.accountId += 1
        return 'account-1'
      },
      get currency() {
        reads.currency += 1
        return 'USD' as const
      },
      get chain() {
        reads.chain += 1
        return 'ETH' as const
      },
      custodyType: 'self',
      ignored: 'not-on-the-wire',
    }

    await client.create(request)

    expect(reads).toEqual({ idempotencyKey: 1, accountId: 1, currency: 1, chain: 1 })
    const body = new TextDecoder().decode(transport.sent[0]?.bodyBytes as Uint8Array)
    expect(body).not.toContain('custodyType')
    expect(body).not.toContain('ignored')
  })

  it('rejects invalid create input before transport', async () => {
    const { client, transport } = clientFor({
      status: 201,
      bodyBytes: envelope(COMPLETE_ADDRESS),
    })
    const valid = {
      idempotencyKey: IDEMPOTENCY_KEY,
      accountId: 'account-1',
      currency: 'USD',
      chain: 'ETH',
    } as const
    const invalid: unknown[] = [
      null,
      [],
      'request',
      { ...valid, idempotencyKey: 'not-a-uuid' },
      { ...valid, idempotencyKey: '22222222-2222-1222-a222-222222222222' },
      { ...valid, idempotencyKey: '22222222-2222-4222-7222-222222222222' },
      { ...valid, accountId: '' },
      { ...valid, accountId: null },
      { ...valid, accountId: undefined },
      { idempotencyKey: valid.idempotencyKey, currency: valid.currency, chain: valid.chain },
      { ...valid, currency: 'USDC' },
      { ...valid, chain: '' },
      { ...valid, chain: null },
    ]

    for (const request of invalid) {
      expect((await detailOf(client.create(request as GenerateAddressRequest))).kind).toBe(
        'contract_violation',
      )
    }
    expect(transport.sent).toHaveLength(0)
  })

  /**
   * The broader public Accounts API permits omitting `accountId` to select
   * the caller's omnibus master account, but this SDK's typed client only
   * supports account-scoped resolution — see `GenerateAddressRequest`'s class
   * doc. A caller who omits `accountId` is rejected locally rather than
   * silently routed to the master account.
   */
  it('rejects create() without accountId rather than falling back to the omnibus master account', async () => {
    const { client, transport } = clientFor({
      status: 201,
      bodyBytes: envelope(COMPLETE_ADDRESS),
    })

    const result = await detailOf(
      client.create({
        idempotencyKey: IDEMPOTENCY_KEY,
        currency: 'USD',
        chain: 'ETH',
      } as GenerateAddressRequest),
    )

    expect(result.kind).toBe('contract_violation')
    expect(transport.sent).toHaveLength(0)
  })

  /**
   * `chain` is optional: the service resolves an omitted `chain` to the
   * account's immutable home blockchain for segregated/self-custody accounts
   * — the only accounts this SDK's typed client reaches (see
   * `GenerateAddressRequest`'s class doc).
   */
  it('creates with chain omitted, letting the service resolve the account home chain', async () => {
    const { client, transport } = clientFor({
      status: 201,
      bodyBytes: envelope(COMPLETE_ADDRESS),
    })

    await client.create({
      idempotencyKey: IDEMPOTENCY_KEY,
      accountId: 'account-1',
      currency: 'USD',
    })

    expect(new TextDecoder().decode(transport.sent[0]?.bodyBytes as Uint8Array)).toBe(
      `{"idempotencyKey":"${IDEMPOTENCY_KEY}","accountId":"account-1","currency":"USD"}`,
    )
  })

  /**
   * A `chain` value outside the author-time `DEPOSIT_ADDRESS_CHAINS` union is
   * a growable-catalog value, not a contract violation — see that constant's
   * doc in `models/GenerateAddressRequest.ts`. The server remains the
   * authority and 400s on a genuinely unsupported chain.
   */
  it('does not reject a chain outside the locally known catalog', async () => {
    const { client, transport } = clientFor({
      status: 201,
      bodyBytes: envelope(COMPLETE_ADDRESS),
    })

    await client.create({
      idempotencyKey: IDEMPOTENCY_KEY,
      accountId: 'account-1',
      currency: 'USD',
      chain: 'BRAND_NEW_CHAIN' as DepositAddressChain,
    })

    expect(new TextDecoder().decode(transport.sent[0]?.bodyBytes as Uint8Array)).toBe(
      `{"idempotencyKey":"${IDEMPOTENCY_KEY}","accountId":"account-1","currency":"USD","chain":"BRAND_NEW_CHAIN"}`,
    )
  })
})

describe('the success path', () => {
  it('accepts the documented 200 status', async () => {
    const { client } = clientFor({ status: 200, bodyBytes: envelope(COMPLETE_ADDRESS) })
    expect((await client.get(VALID_ID)).id).toBe(VALID_ID)
  })

  /** The payload sits under `data`; a body with it at the root is malformed. */
  it('rejects a body whose address sits at the root instead of the envelope', async () => {
    const { client } = clientFor({
      status: 200,
      headers: { 'X-Request-Id': 'req-2' },
      bodyBytes: bytes(COMPLETE_ADDRESS),
    })

    expect(await detailOf(client.get(VALID_ID))).toEqual({
      kind: 'contract_violation',
      correlationId: 'req-2',
    })
  })

  /** An envelope present but empty is malformed — the wrapper is not optional on a 2xx. */
  it('rejects an empty envelope, an empty body, and no body at all', async () => {
    for (const bodyBytes of [bytes('{"data":null}'), bytes(''), null]) {
      const { client } = clientFor({ status: 200, bodyBytes })
      expect((await detailOf(client.get(VALID_ID))).kind).toBe('contract_violation')
    }
  })

  /**
   * A `200` whose address is missing something every source guarantees must
   * reach the caller as a broken contract, not a successful address with a
   * hole in it. The correlation id has to survive.
   */
  it('reports an address missing guaranteed fields as a broken contract with the correlation id', async () => {
    const payloads = ['{}', `{"id":"${VALID_ID}"}`, `{"id":"${VALID_ID}","address":"0xRECEIVE"}`]

    for (const payload of payloads) {
      const { client } = clientFor({
        status: 200,
        headers: { 'X-Request-Id': 'req-13' },
        bodyBytes: envelope(payload),
      })
      expect(await detailOf(client.get(VALID_ID))).toEqual({
        kind: 'contract_violation',
        correlationId: 'req-13',
      })
    }
  })

  /** The fields a segregated/self-custody read may leave null must still surface as null, not fail the read. */
  it('surfaces a segregated/self-custody read that omits currency and addressTag', async () => {
    const { client } = okClient(
      `{"id":"${VALID_ID}","address":"0xabc","chain":"ETH","addressTag":null,"currency":null,` +
        '"accountId":"acct-1"}',
    )

    const address = await client.get(VALID_ID)

    expect(address.address).toBe('0xabc')
    expect(address.currency).toBeNull()
    expect(address.addressTag).toBeNull()
    expect(address.accountId).toBe('acct-1')
  })

  it('requires exactly 201 and a data envelope for create', async () => {
    for (const status of [200, 202, 204, 299]) {
      const { client } = clientFor({ status, bodyBytes: envelope(COMPLETE_ADDRESS) })
      expect(
        (
          await detailOf(
            client.create({
              idempotencyKey: IDEMPOTENCY_KEY,
              accountId: 'account-1',
              currency: 'USD',
              chain: 'ETH',
            }),
          )
        ).kind,
      ).toBe('api')
    }

    for (const bodyBytes of [bytes(COMPLETE_ADDRESS), bytes('{"data":null}'), bytes(''), null]) {
      const { client } = clientFor({
        status: 201,
        headers: { 'x-request-id': 'req-create-bad' },
        bodyBytes,
      })
      expect(
        await detailOf(
          client.create({
            idempotencyKey: IDEMPOTENCY_KEY,
            accountId: 'account-1',
            currency: 'USD',
            chain: 'ETH',
          }),
        ),
      ).toEqual({ kind: 'contract_violation', correlationId: 'req-create-bad' })
    }
  })
})

describe('the failure path', () => {
  it('maps a status other than 200 onto the api error carrying the status', async () => {
    for (const status of [201, 204, 299, 400, 401, 404, 409, 500, 503]) {
      const { client } = clientFor({
        status,
        headers: { 'X-Request-Id': `req-${status}` },
        bodyBytes: bytes(`{"status":{"code":${status * 10},"message":"nope"}}`),
      })

      const detail = await detailOf(client.get(VALID_ID))
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
      [429, true],
      [500, true],
      [599, true],
    ] as const) {
      const { client } = clientFor({ status })
      expect(await detailOf(client.get(VALID_ID))).toMatchObject({ kind: 'api', retryable })
    }
  })

  /** No field name from the response reaches the error a consumer sees. */
  it('does not put a response field name in the error message', async () => {
    const { client } = clientFor({ status: 200, bodyBytes: envelope(`{"id":"${VALID_ID}"}`) })

    try {
      await client.get(VALID_ID)
      throw new Error('expected the read to fail')
    } catch (err) {
      expect(isDaaError(err)).toBe(true)
      expect((err as Error).message).not.toContain('address')
      expect((err as Error).message).not.toContain('chain')
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
      createDaaUserClient(transport, 'production', NO_SIGNING).depositAddresses.get(VALID_ID),
    ).rejects.toMatchObject({
      detail: { kind: 'transport', retryable: true },
      cause: failure,
    })
  })

  it('maps a create reusing a key for a different account to idempotency_conflict with that key', async () => {
    const { client, transport } = clientFor({
      status: 409,
      headers: { 'X-Request-Id': 'req-reused' },
      bodyBytes: bytes(
        '{"code":420034,"message":"The idempotency key was reused with a different request"}',
      ),
    })

    const call = client.create({
      idempotencyKey: IDEMPOTENCY_KEY,
      accountId: '1000662322',
      currency: 'USD',
      chain: 'ETH',
    })

    await expect(call).rejects.toMatchObject({
      detail: { kind: 'idempotency_conflict', idempotencyKey: IDEMPOTENCY_KEY },
    })
    await expect(call).rejects.not.toHaveProperty(
      'message',
      expect.stringContaining(IDEMPOTENCY_KEY),
    )
    expect(transport.sent).toHaveLength(1)
  })

  it('preserves authoritative and unknown create API failures and transport failures', async () => {
    const { client } = clientFor({
      status: 400,
      headers: { 'x-request-id': 'req-conflict' },
      bodyBytes: bytes('{"status":{"code":420034}}'),
    })
    const request: GenerateAddressRequest = {
      idempotencyKey: IDEMPOTENCY_KEY,
      accountId: 'account-1',
      currency: 'USD',
      chain: 'ETH',
    }

    expect(await detailOf(client.create(request))).toEqual({
      kind: 'api',
      httpStatus: 400,
      daaStatusCode: 420034,
      retryable: false,
    })

    const { client: unknownConflict } = clientFor({
      status: 409,
      bodyBytes: bytes('{"status":{"code":"SOME_NEW_CONFLICT"}}'),
    })
    expect(await detailOf(unknownConflict.create(request))).toEqual({
      kind: 'api',
      httpStatus: 409,
      daaStatusCode: 'SOME_NEW_CONFLICT',
      retryable: false,
    })

    const failure = new Error('relay unavailable')
    const transport: DaaTransport = {
      async send() {
        throw failure
      },
    }
    await expect(
      createDaaUserClient(transport, 'production', NO_SIGNING).depositAddresses.create(request),
    ).rejects.toMatchObject({
      detail: { kind: 'transport', retryable: true, idempotencyKey: IDEMPOTENCY_KEY },
      cause: failure,
    })
  })
})

describe('construction', () => {
  it('freezes the client', () => {
    const transport: DaaTransport = {
      async send() {
        return { status: 200, headers: {}, bodyBytes: null }
      },
    }
    expect(
      Object.isFrozen(createDaaUserClient(transport, 'production', NO_SIGNING).depositAddresses),
    ).toBe(true)
  })
})
