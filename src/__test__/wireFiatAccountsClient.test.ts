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
import { isDaaError } from '../errors'
import type { DaaSdkError } from '../errors'
import type { WireFiatAccountsClient } from '../api/WireFiatAccountsClient'
import type { DaaHttpRequest, DaaHttpResponse, DaaTransport } from '../transport/DaaTransport'
import { NO_SIGNING } from './userClientSigning'

/**
 * The wire fiat-account reads, end to end through the client: request shape,
 * envelope, decoding, and status mapping. Mirrors `withdrawalsClient.test.ts`
 * / `depositsClient.test.ts`. Reached through the internal user-client
 * factory, the same path `DaaClient.forUser` uses. A read must not resolve the
 * AuthKey — `NO_SIGNING` throws if anything tries — because fiat-account
 * list/get and instructions reads are ordinary typed reads with no device
 * signature.
 */

class RecordingTransport implements DaaTransport {
  readonly sent: DaaHttpRequest[] = []

  constructor(private readonly response: DaaHttpResponse) {}

  async send(request: DaaHttpRequest): Promise<DaaHttpResponse> {
    this.sent.push(request)
    return this.response
  }
}

const FIAT_ACCOUNT_ID = '3f1a2b4c-5d6e-4f70-8192-a3b4c5d6e7f8'
const CLIENT_ENTITY_ID = '11111111-1111-4111-8111-111111111111'

const COMPLETE_WIRE =
  '{"id":"3f1a2b4c-5d6e-4f70-8192-a3b4c5d6e7f8","status":"complete",' +
  '"description":"WELLS FARGO BANK, NA ****0010","trackingRef":"CIR1",' +
  '"fingerprint":"eb170539-9e1c-4e92-bf4f-1d09534fdca2",' +
  '"billingDetails":{"name":"Satoshi Nakamoto","city":"Boston","country":"US",' +
  '"line1":"100 Money Street","postalCode":"01234"},' +
  '"createDate":"2026-01-01T00:00:00Z","updateDate":"2026-01-02T00:00:00Z"}'

const COMPLETE_INSTRUCTION =
  '{"trackingRef":"CIR1","beneficiary":{"name":"CIRCLE INTERNET FINANCIAL INC"},' +
  '"beneficiaryBank":{"routingNumber":"121000248","accountNumber":"****7427"}}'

function bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text)
}

function envelope(payload: string): Uint8Array {
  return bytes(`{"data":${payload}}`)
}

function clientFor(response: Partial<DaaHttpResponse>): {
  wires: WireFiatAccountsClient
  transport: RecordingTransport
} {
  const transport = new RecordingTransport({
    status: response.status ?? 200,
    headers: response.headers ?? {},
    bodyBytes: response.bodyBytes ?? null,
  })
  return {
    wires: createDaaUserClient(transport, 'production', NO_SIGNING).fiatAccounts.wires,
    transport,
  }
}

function okClient(payload: string) {
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
    if (isDaaError(err)) return err.detail
    throw err
  }
  throw new Error('expected the operation to fail')
}

describe('wires.list', () => {
  it('reads the unpaginated collection over the public wires path with no query by default', async () => {
    const { wires, transport } = okClient(`[${COMPLETE_WIRE}]`)

    const result = await wires.list()

    expect(transport.sent).toEqual([
      { method: 'GET', path: '/v1/banks/wires', query: null, headers: {}, bodyBytes: null },
    ])
    expect(result).toHaveLength(1)
    expect(result[0]?.id).toBe(FIAT_ACCOUNT_ID)
    // Plain array, not this SDK's opaque-cursor Page<T>.
    expect(Array.isArray(result)).toBe(true)
    expect((result as unknown as { next?: unknown }).next).toBeUndefined()
  })

  it('sends clientEntityId as an optional exact query when supplied', async () => {
    const { wires, transport } = okClient('[]')

    await wires.list({ clientEntityId: CLIENT_ENTITY_ID })

    expect(transport.sent[0]?.query).toBe(`clientEntityId=${CLIENT_ENTITY_ID}`)
  })

  it('rejects a non-UUID clientEntityId locally without sending a request', async () => {
    const { wires, transport } = okClient('[]')

    expect((await detailOf(wires.list({ clientEntityId: 'not-a-uuid' }))).kind).toBe(
      'contract_violation',
    )
    expect(transport.sent).toHaveLength(0)
  })

  it('rejects a non-object query locally without sending a request', async () => {
    const { wires, transport } = okClient('[]')

    expect((await detailOf(wires.list(['not', 'an', 'object'] as never))).kind).toBe(
      'contract_violation',
    )
    expect(transport.sent).toHaveLength(0)
  })
})

describe('wires.get', () => {
  it('reads one wire over the public by-id path with an empty unsigned GET', async () => {
    const { wires, transport } = okClient(COMPLETE_WIRE)

    const wire = await wires.get(FIAT_ACCOUNT_ID)

    expect(transport.sent).toEqual([
      {
        method: 'GET',
        path: `/v1/banks/wires/${FIAT_ACCOUNT_ID}`,
        query: null,
        headers: {},
        bodyBytes: null,
      },
    ])
    expect(wire.id).toBe(FIAT_ACCOUNT_ID)
    expect(wire.status).toEqual({ kind: 'complete' })
  })

  it('rejects a non-UUID fiatAccountId locally without sending a request', async () => {
    const { wires, transport } = okClient(COMPLETE_WIRE)

    for (const bad of ['', 'wire-1', `${FIAT_ACCOUNT_ID}/other`, `${FIAT_ACCOUNT_ID}%2Fother`]) {
      expect((await detailOf(wires.get(bad))).kind).toBe('contract_violation')
    }
    expect(transport.sent).toHaveLength(0)
  })

  it('accepts only the documented 200', async () => {
    const { wires } = clientFor({ status: 201, bodyBytes: envelope(COMPLETE_WIRE) })
    const detail = await detailOf(wires.get(FIAT_ACCOUNT_ID))
    expect(detail).toMatchObject({ kind: 'api', httpStatus: 201 })
  })
})

describe('wires.getInstructions', () => {
  it('reads instructions over the public instructions path with no query by default', async () => {
    const { wires, transport } = okClient(COMPLETE_INSTRUCTION)

    const instruction = await wires.getInstructions(FIAT_ACCOUNT_ID)

    expect(transport.sent).toEqual([
      {
        method: 'GET',
        path: `/v1/banks/wires/${FIAT_ACCOUNT_ID}/instructions`,
        query: null,
        headers: {},
        bodyBytes: null,
      },
    ])
    expect(instruction.trackingRef).toBe('CIR1')
    expect(instruction.beneficiaryBank?.routingNumber).toBe('121000248')
  })

  it('sends the optional public accountId query exactly, including a numeric string', async () => {
    const { wires, transport } = okClient(COMPLETE_INSTRUCTION)

    await wires.getInstructions(FIAT_ACCOUNT_ID, { accountId: '1000662322' })

    expect(transport.sent[0]?.query).toBe('accountId=1000662322')
  })

  it('rejects an empty accountId locally without sending a request', async () => {
    const { wires, transport } = okClient(COMPLETE_INSTRUCTION)

    expect((await detailOf(wires.getInstructions(FIAT_ACCOUNT_ID, { accountId: '' }))).kind).toBe(
      'contract_violation',
    )
    expect(transport.sent).toHaveLength(0)
  })

  it('rejects a non-object query locally without sending a request', async () => {
    const { wires, transport } = okClient(COMPLETE_INSTRUCTION)

    expect((await detailOf(wires.getInstructions(FIAT_ACCOUNT_ID, 'nope' as never))).kind).toBe(
      'contract_violation',
    )
    expect(transport.sent).toHaveLength(0)
  })

  it('rejects a non-UUID fiatAccountId locally without sending a request', async () => {
    const { wires, transport } = okClient(COMPLETE_INSTRUCTION)
    expect((await detailOf(wires.getInstructions('not-a-uuid'))).kind).toBe('contract_violation')
    expect(transport.sent).toHaveLength(0)
  })
})

describe('failure mapping', () => {
  it('maps a status other than 200 onto the api error carrying the status', async () => {
    const { wires } = clientFor({ status: 404, bodyBytes: bytes('{"status":{"code":4004}}') })
    expect(await detailOf(wires.get(FIAT_ACCOUNT_ID))).toMatchObject({
      kind: 'api',
      httpStatus: 404,
      daaStatusCode: 4004,
    })
  })

  it('reports a consumer transport failure as a transport error with it as the cause', async () => {
    const failure = new Error('dns')
    const transport: DaaTransport = {
      async send() {
        throw failure
      },
    }
    await expect(
      createDaaUserClient(transport, 'production', NO_SIGNING).fiatAccounts.wires.get(
        FIAT_ACCOUNT_ID,
      ),
    ).rejects.toMatchObject({
      detail: { kind: 'transport', retryable: true },
      cause: failure,
    })
  })
})
