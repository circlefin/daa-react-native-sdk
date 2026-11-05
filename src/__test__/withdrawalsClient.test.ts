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

import { WithdrawalsClient } from '../api/WithdrawalsClient'
import { isDaaError } from '../errors'
import type { DaaSdkError } from '../errors'
import type { DaaHttpRequest, DaaHttpResponse, DaaTransport } from '../transport/DaaTransport'
import { NO_SIGNING } from './userClientSigning'

class RecordingTransport implements DaaTransport {
  readonly sent: DaaHttpRequest[] = []

  constructor(private readonly response: DaaHttpResponse) {}

  async send(request: DaaHttpRequest): Promise<DaaHttpResponse> {
    this.sent.push(request)
    return this.response
  }
}

const WITHDRAWAL_ID = 'a49f9b1d-75e0-44a9-b8d2-4293b3f11ebd'
const PAYLOAD =
  '{"id":"a49f9b1d-75e0-44a9-b8d2-4293b3f11ebd",' +
  '"sourceAccountId":"1000662322",' +
  '"destination":{"type":"wire","id":"0db1c81a-d36d-4777-8774-9682d96d82c8"},' +
  '"amount":{"amount":"10.00","currency":"USD"},"status":"pending",' +
  '"createDate":"2026-01-01T00:00:00Z"}'

function bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text)
}

function clientFor(status = 200, body = `{"data":${PAYLOAD}}`) {
  const transport = new RecordingTransport({ status, headers: {}, bodyBytes: bytes(body) })
  // A read must not resolve the AuthKey; `NO_SIGNING` throws if it tries.
  return {
    withdrawals: new WithdrawalsClient(transport, 'https://api.circle.com', NO_SIGNING),
    transport,
  }
}

async function detailOf(operation: Promise<unknown>): Promise<DaaSdkError> {
  try {
    await operation
  } catch (error) {
    if (isDaaError(error)) return error.detail
    throw error
  }
  throw new Error('expected failure')
}

describe('withdrawals get', () => {
  it('uses the public route with an empty unsigned GET', async () => {
    const { withdrawals, transport } = clientFor()
    const result = await withdrawals.get(WITHDRAWAL_ID)

    expect(result.id).toBe(WITHDRAWAL_ID)
    expect(transport.sent).toEqual([
      {
        method: 'GET',
        path: `/v1/accounts/withdrawals/${WITHDRAWAL_ID}`,
        query: null,
        headers: {},
        bodyBytes: null,
      },
    ])
  })

  it('rejects non-UUID identifiers without transport', async () => {
    const { withdrawals, transport } = clientFor()
    for (const bad of ['', 'withdrawal-1', `${WITHDRAWAL_ID}/other`, `${WITHDRAWAL_ID}%2Fother`]) {
      expect((await detailOf(withdrawals.get(bad))).kind).toBe('contract_violation')
    }
    expect(transport.sent).toHaveLength(0)
  })

  it('accepts only the documented 200', async () => {
    for (const status of [201, 204, 299]) {
      const { withdrawals } = clientFor(status)
      const detail = await detailOf(withdrawals.get(WITHDRAWAL_ID))
      expect(detail.kind).toBe('api')
      if (detail.kind === 'api') expect(detail.httpStatus).toBe(status)
    }
  })

  it('maps a malformed data envelope to a contract violation', async () => {
    const { withdrawals } = clientFor(200, '{}')
    expect((await detailOf(withdrawals.get(WITHDRAWAL_ID))).kind).toBe('contract_violation')
  })
})
