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
import { contractViolation, DaaError, isDaaError, transportFailure } from '../errors'
import type { CreateTransferRequest } from '../models/CreateTransferRequest'
import type { DaaHttpRequest, DaaHttpResponse, DaaTransport } from '../transport/DaaTransport'
import { NO_SIGNING, registeredAuthKey, signingFor } from './userClientSigning'

/**
 * The SDK's `transport` error: what a `DaaUserClient` operation throws when
 * the consumer's transport throws instead of returning a response.
 */

const IDEMPOTENCY_KEY = '22222222-2222-4222-a222-222222222222'
const AUTH_KEY_ID = '11111111-1111-4111-8111-111111111111'
const TRANSFER_ID = '33333333-3333-4333-8333-333333333333'

const CREATED_TRANSFER =
  '{"data":{"id":"tr-1","source":{"type":"account","id":"acct-src"},' +
  '"destination":{"type":"account","id":"acct-dst"},' +
  '"amount":{"amount":"10.25","currency":"USD"},"status":"pending"}}'

const VALID_REQUEST: CreateTransferRequest = {
  idempotencyKey: IDEMPOTENCY_KEY,
  destination: { type: 'account', id: 'acct-dst' },
  amount: { amount: '10.25', currency: 'USD' },
}

/** Throws `failures` in order, then answers with `response`. Records every request. */
class FlakyTransport implements DaaTransport {
  readonly sent: DaaHttpRequest[] = []

  constructor(
    private readonly failures: unknown[],
    private readonly response: DaaHttpResponse = { status: 500, headers: {}, bodyBytes: null },
  ) {}

  async send(request: DaaHttpRequest): Promise<DaaHttpResponse> {
    this.sent.push(request)
    if (this.failures.length > 0) {
      throw this.failures.shift()
    }
    return this.response
  }
}

async function caught(operation: Promise<unknown>): Promise<DaaError> {
  const err = await operation.then(
    () => {
      throw new Error('expected the operation to fail')
    },
    (e: unknown) => e,
  )
  if (!isDaaError(err)) {
    throw new Error(`expected a DaaError, got ${String(err)}`)
  }
  return err
}

describe('transportFailure', () => {
  it('is retryable, carries the key only when given, and keeps the cause off message', () => {
    const cause = new Error('connect ECONNREFUSED 10.0.0.7:8443 Authorization: Bearer secret')

    const keyed = transportFailure(cause, IDEMPOTENCY_KEY)
    expect(keyed.detail).toEqual({
      kind: 'transport',
      retryable: true,
      idempotencyKey: IDEMPOTENCY_KEY,
    })
    expect(transportFailure(cause).detail).toEqual({ kind: 'transport', retryable: true })

    expect(keyed.cause).toBe(cause)
    expect(keyed.message).toBe('DAA: the transport failed before a response was received')
    expect(Object.getOwnPropertyDescriptor(keyed, 'cause')?.enumerable).toBe(false)
    expect(JSON.stringify(keyed)).not.toContain('secret')
  })
})

describe('DaaUserClient transport failures', () => {
  it('reports a failed read as transport, with no idempotency key', async () => {
    const failure = new Error('dns')
    const transport = new FlakyTransport([failure])

    const err = await caught(
      createDaaUserClient(transport, 'production', NO_SIGNING).transfers.get(TRANSFER_ID),
    )

    expect(err.detail).toEqual({ kind: 'transport', retryable: true })
    expect(err.cause).toBe(failure)
  })

  it('reports a failed signed create with the key the retry must reuse', async () => {
    const failure = new Error('socket hang up')
    const transport = new FlakyTransport([failure])
    const signing = signingFor(await registeredAuthKey(), AUTH_KEY_ID)

    const err = await caught(
      createDaaUserClient(transport, 'production', signing).transfers.create(VALID_REQUEST),
    )

    expect(err.detail).toEqual({
      kind: 'transport',
      retryable: true,
      idempotencyKey: IDEMPOTENCY_KEY,
    })
    expect(err.cause).toBe(failure)
  })

  it('lets the same request be resent with the same body bytes after a transport failure', async () => {
    const transport = new FlakyTransport([new Error('timeout')], {
      status: 201,
      headers: { Location: '/v1/accounts/transfers/tr-1' },
      bodyBytes: new TextEncoder().encode(CREATED_TRANSFER),
    })
    const signing = signingFor(await registeredAuthKey(), AUTH_KEY_ID)
    const transfers = createDaaUserClient(transport, 'production', signing).transfers

    const err = await caught(transfers.create(VALID_REQUEST))
    expect(err.detail).toMatchObject({ kind: 'transport', retryable: true })
    await expect(transfers.create(VALID_REQUEST)).resolves.toMatchObject({ id: 'tr-1' })

    expect(transport.sent).toHaveLength(2)
    expect(transport.sent[1]?.bodyBytes).toEqual(transport.sent[0]?.bodyBytes)
  })

  it('reports a failed signed context refresh as transport, with no idempotency key', async () => {
    const failure = new Error('offline')
    const signing = signingFor(await registeredAuthKey(), AUTH_KEY_ID)

    const err = await caught(
      createDaaUserClient(new FlakyTransport([failure]), 'production', signing).refreshContext(),
    )

    expect(err.detail).toEqual({ kind: 'transport', retryable: true })
    expect(err.cause).toBe(failure)
  })

  it('reports a failed page follow as transport, with no idempotency key', async () => {
    const failure = new Error('connection reset')
    const firstPage: DaaHttpResponse = {
      status: 200,
      headers: {
        Link: '<https://api.circle.com/v1/accounts/transfers?pageAfter=opaque>; rel="next"',
      },
      bodyBytes: new TextEncoder().encode(
        '{"data":[{"id":"tr-1","source":{"type":"account","id":"1000662322"},' +
          '"destination":{"type":"blockchain","chain":"ETH","address":"0xdest"},' +
          '"amount":{"amount":"10.00","currency":"USDC"},"status":"pending"}]}',
      ),
    }
    let calls = 0
    const transport: DaaTransport = {
      async send() {
        calls += 1
        if (calls === 1) return firstPage
        throw failure
      },
    }

    const page = await createDaaUserClient(transport, 'production', NO_SIGNING).transfers.list()
    const err = await caught(page.next())

    expect(err.detail).toEqual({ kind: 'transport', retryable: true })
    expect(err.cause).toBe(failure)
  })

  it('passes a DaaError the transport threw through unchanged', async () => {
    const own = contractViolation('relay refused the request')
    const transport = new FlakyTransport([own])

    await expect(
      createDaaUserClient(transport, 'production', NO_SIGNING).transfers.get(TRANSFER_ID),
    ).rejects.toBe(own)
  })

  it('does not report a closed client as a transport failure', async () => {
    const transport = new FlakyTransport([])
    const user = createDaaUserClient(transport, 'production', NO_SIGNING)
    user.close()

    const err = await caught(user.transfers.get(TRANSFER_ID))

    expect(err.detail).toEqual({ kind: 'contract_violation' })
    expect(transport.sent).toHaveLength(0)
  })
})
