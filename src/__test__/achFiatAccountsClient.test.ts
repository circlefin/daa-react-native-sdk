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
import type { AchFiatAccountsClient } from '../api/AchFiatAccountsClient'
import type { DaaHttpRequest, DaaHttpResponse, DaaTransport } from '../transport/DaaTransport'
import { NO_SIGNING } from './userClientSigning'

/**
 * The ACH fiat-account reads, mirroring `wireFiatAccountsClient.test.ts`. The
 * one behavioral difference under test throughout: `clientEntityId` is
 * **required** for `ach.list`, unlike `wires.list` —
 * `AchFiatAccountListQuery` types it as a non-optional field, not `?`.
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

const COMPLETE_ACH =
  '{"id":"3f1a2b4c-5d6e-4f70-8192-a3b4c5d6e7f8","status":"complete",' +
  '"description":"WELLS FARGO BANK, NA ****0010","trackingRef":"CIR1",' +
  '"fingerprint":"eb170539-9e1c-4e92-bf4f-1d09534fdca2",' +
  '"billingDetails":{"name":"Satoshi Nakamoto","city":"Boston","country":"US",' +
  '"line1":"100 Money Street","postalCode":"01234"},' +
  '"routingNumber":"121000248",' +
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
  ach: AchFiatAccountsClient
  transport: RecordingTransport
} {
  const transport = new RecordingTransport({
    status: response.status ?? 200,
    headers: response.headers ?? {},
    bodyBytes: response.bodyBytes ?? null,
  })
  return {
    ach: createDaaUserClient(transport, 'production', NO_SIGNING).fiatAccounts.ach,
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

describe('ach.list', () => {
  it('requires clientEntityId and sends it as the exact query', async () => {
    const { ach, transport } = okClient(`[${COMPLETE_ACH}]`)

    const result = await ach.list({ clientEntityId: CLIENT_ENTITY_ID })

    expect(transport.sent).toEqual([
      {
        method: 'GET',
        path: '/v1/banks/ach',
        query: `clientEntityId=${CLIENT_ENTITY_ID}`,
        headers: {},
        bodyBytes: null,
      },
    ])
    // The full ACH projection, not a leaner list-only summary.
    expect(result[0]?.routingNumber).toBe('121000248')
  })

  it('rejects a call with no query object at all, without sending a request', async () => {
    const { ach, transport } = okClient('[]')

    // @ts-expect-error — exercising the runtime guard for a caller that
    // bypasses the compile-time requirement (plain JS, or an `any`).
    expect((await detailOf(ach.list(undefined))).kind).toBe('contract_violation')
    expect(transport.sent).toHaveLength(0)
  })

  it('rejects a query object missing clientEntityId, without sending a request', async () => {
    const { ach, transport } = okClient('[]')

    // @ts-expect-error — same runtime guard, this time for an object missing
    // the one required field.
    expect((await detailOf(ach.list({}))).kind).toBe('contract_violation')
    expect(transport.sent).toHaveLength(0)
  })

  it('rejects a non-UUID clientEntityId, without sending a request', async () => {
    const { ach, transport } = okClient('[]')

    expect((await detailOf(ach.list({ clientEntityId: 'not-a-uuid' }))).kind).toBe(
      'contract_violation',
    )
    expect(transport.sent).toHaveLength(0)
  })
})

describe('ach.get', () => {
  it('reads one ACH account over the public by-id path with an empty unsigned GET', async () => {
    const { ach, transport } = okClient(COMPLETE_ACH)

    const account = await ach.get(FIAT_ACCOUNT_ID)

    expect(transport.sent).toEqual([
      {
        method: 'GET',
        path: `/v1/banks/ach/${FIAT_ACCOUNT_ID}`,
        query: null,
        headers: {},
        bodyBytes: null,
      },
    ])
    expect(account.id).toBe(FIAT_ACCOUNT_ID)
    expect(account.status).toEqual({ kind: 'complete' })
  })

  it('rejects a non-UUID fiatAccountId locally without sending a request', async () => {
    const { ach, transport } = okClient(COMPLETE_ACH)

    for (const bad of ['', 'ach-1', `${FIAT_ACCOUNT_ID}/other`, `${FIAT_ACCOUNT_ID}%2Fother`]) {
      expect((await detailOf(ach.get(bad))).kind).toBe('contract_violation')
    }
    expect(transport.sent).toHaveLength(0)
  })

  it('accepts only the documented 200', async () => {
    const { ach } = clientFor({ status: 201, bodyBytes: envelope(COMPLETE_ACH) })
    const detail = await detailOf(ach.get(FIAT_ACCOUNT_ID))
    expect(detail).toMatchObject({ kind: 'api', httpStatus: 201 })
  })
})

describe('ach.getInstructions', () => {
  it('reads instructions over the public instructions path and accepts no query parameter', async () => {
    const { ach, transport } = okClient(COMPLETE_INSTRUCTION)

    const instruction = await ach.getInstructions(FIAT_ACCOUNT_ID)

    // Unlike `wires.getInstructions`, the ACH route has no public `accountId`
    // — the SDK method signature carries no query parameter at all.
    expect(transport.sent).toEqual([
      {
        method: 'GET',
        path: `/v1/banks/ach/${FIAT_ACCOUNT_ID}/instructions`,
        query: null,
        headers: {},
        bodyBytes: null,
      },
    ])
    expect(instruction.trackingRef).toBe('CIR1')
    expect(instruction.beneficiaryBank?.routingNumber).toBe('121000248')
  })

  it('rejects a non-UUID fiatAccountId locally without sending a request', async () => {
    const { ach, transport } = okClient(COMPLETE_INSTRUCTION)
    expect((await detailOf(ach.getInstructions('not-a-uuid'))).kind).toBe('contract_violation')
    expect(transport.sent).toHaveLength(0)
  })
})

describe('failure mapping', () => {
  it('maps a status other than 200 onto the api error carrying the status', async () => {
    const { ach } = clientFor({ status: 404, bodyBytes: bytes('{"status":{"code":4004}}') })
    expect(await detailOf(ach.get(FIAT_ACCOUNT_ID))).toMatchObject({
      kind: 'api',
      httpStatus: 404,
      daaStatusCode: 4004,
    })
  })

  /**
   * An environment may lack `GET /v1/banks/ach` entirely; see
   * `AchFiatAccountsClient`'s class doc: this SDK does not distinguish that
   * from any other `api` failure.
   */
  it('surfaces a missing route as an ordinary api error, not a distinguished capability error', async () => {
    const { ach } = clientFor({ status: 404, bodyBytes: bytes('{}') })
    const detail = await detailOf(ach.list({ clientEntityId: CLIENT_ENTITY_ID }))
    expect(detail).toMatchObject({ kind: 'api', httpStatus: 404 })
  })

  it('reports a consumer transport failure as a transport error with it as the cause', async () => {
    const failure = new Error('dns')
    const transport: DaaTransport = {
      async send() {
        throw failure
      },
    }
    await expect(
      createDaaUserClient(transport, 'production', NO_SIGNING).fiatAccounts.ach.get(
        FIAT_ACCOUNT_ID,
      ),
    ).rejects.toMatchObject({
      detail: { kind: 'transport', retryable: true },
      cause: failure,
    })
  })
})
