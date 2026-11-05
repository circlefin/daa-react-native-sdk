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
import { loginStepFailure } from '../api/loginFailure'
import { isDaaError } from '../errors'
import type { DaaSdkError } from '../errors'
import type { CreateAccountRequest } from '../models/CreateAccountRequest'
import type { CreateTransferRequest } from '../models/CreateTransferRequest'
import type { CreateWithdrawalRequest } from '../models/CreateWithdrawalRequest'
import type { DaaHttpRequest, DaaHttpResponse, DaaTransport } from '../transport/DaaTransport'
import { DAA_STATUS_CODES, isDaaStatus, type DaaStatusName } from '../wire/daaStatusCodes'
import { readDaaStatusCode } from '../wire/errorEnvelope'
import { registeredAuthKey, signingFor } from './userClientSigning'

/**
 * DAA's real error bodies, through the real clients.
 *
 * DAA sends `{"code":<int32>,"message":…,"externalMessage":…}` — a flat error
 * object with the code at the root, never a name string. The SDK classifies on
 * that number only, so a name string in a fixture would test the `api`
 * fallback, not the mapping. Every code here is a literal, not
 * a read of `DAA_STATUS_CODES`, so a wrong number in the table fails these
 * tests instead of moving with them.
 */

class SequenceTransport implements DaaTransport {
  readonly sent: DaaHttpRequest[] = []

  constructor(private readonly responses: DaaHttpResponse[]) {}

  async send(request: DaaHttpRequest): Promise<DaaHttpResponse> {
    this.sent.push(request)
    const next = this.responses.shift()
    if (next === undefined) {
      throw new Error('transport has no more responses')
    }
    return next
  }
}

const AUTH_KEY_ID = '11111111-1111-4111-8111-111111111111'
const IDEMPOTENCY_KEY = '22222222-2222-4222-a222-222222222222'
const CLIENT_ENTITY_ID = '33333333-3333-4333-b333-333333333333'
const DESTINATION_ID = '55555555-5555-4555-8555-555555555555'
const REQUEST_ID = 'req-daa-1'

function bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text)
}

/** The error body DAA actually sends. */
function daaError(code: number): Uint8Array {
  return bytes(
    `{"code":${code},"message":"internal detail","externalMessage":"The request was rejected"}`,
  )
}

function failure(status: number, code: number): DaaHttpResponse {
  return { status, headers: { 'X-Request-Id': REQUEST_ID }, bodyBytes: daaError(code) }
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

const ACCOUNT_REQUEST: CreateAccountRequest = {
  idempotencyKey: IDEMPOTENCY_KEY,
  clientEntityId: CLIENT_ENTITY_ID,
  custodyType: 'self',
  type: 'third_party',
  purpose: 'custody',
  description: 'Primary',
  blockchain: 'ARC',
}

const TRANSFER_REQUEST: CreateTransferRequest = {
  idempotencyKey: IDEMPOTENCY_KEY,
  destination: { type: 'account', id: 'acct-dst' },
  amount: { amount: '10.25', currency: 'USD' },
}

const WITHDRAWAL_REQUEST: CreateWithdrawalRequest = {
  idempotencyKey: IDEMPOTENCY_KEY,
  destination: { type: 'wire', id: DESTINATION_ID },
  amount: { amount: '10.25', currency: 'USD' },
}

type SignedCall = (responses: DaaHttpResponse[]) => Promise<{
  transport: SequenceTransport
  call: Promise<unknown>
}>

async function userClient(responses: DaaHttpResponse[]) {
  const transport = new SequenceTransport(responses)
  const signing = signingFor(await registeredAuthKey(), AUTH_KEY_ID)
  return { transport, user: createDaaUserClient(transport, 'production', signing) }
}

const SIGNED_WRITES: ReadonlyArray<[string, SignedCall]> = [
  [
    'accounts.create',
    async (responses) => {
      const { transport, user } = await userClient(responses)
      return { transport, call: user.accounts.create(ACCOUNT_REQUEST) }
    },
  ],
  [
    'transfers.create',
    async (responses) => {
      const { transport, user } = await userClient(responses)
      return { transport, call: user.transfers.create(TRANSFER_REQUEST) }
    },
  ],
  [
    'withdrawals.create',
    async (responses) => {
      const { transport, user } = await userClient(responses)
      return { transport, call: user.withdrawals.create(WITHDRAWAL_REQUEST) }
    },
  ],
]

const REFRESH_CONTEXT: SignedCall = async (responses) => {
  const { transport, user } = await userClient(responses)
  return { transport, call: user.refreshContext() }
}

const SIGNED_CALLS: ReadonlyArray<[string, SignedCall]> = [
  ...SIGNED_WRITES,
  ['refreshContext', REFRESH_CONTEXT],
]

/**
 * Name strings, which classify as `api`. Every non-numeric string takes the
 * same path, so two cover it: the name of a row that has a numeric code, and
 * the name of a condition that has no code.
 */
const NAME_STRINGS = ['IDEMPOTENCY_KEY_REUSED', 'DEVICE_AUTHORIZATION_EXPIRED'] as const

function failureBody(status: number, body: string): DaaHttpResponse {
  return { status, headers: { 'X-Request-Id': REQUEST_ID }, bodyBytes: bytes(body) }
}

describe('readDaaStatusCode', () => {
  it('reads the root code of the flat body DAA sends', () => {
    expect(readDaaStatusCode(daaError(420034))).toBe(420034)
  })

  it('reads status.code when the root code is absent', () => {
    expect(readDaaStatusCode(bytes('{"status":{"code":420034}}'))).toBe(420034)
    expect(readDaaStatusCode(bytes('{"status":{"code":"IDEMPOTENCY_KEY_REUSED"}}'))).toBe(
      'IDEMPOTENCY_KEY_REUSED',
    )
    // A JSON null is not a present root code.
    expect(readDaaStatusCode(bytes('{"code":null,"status":{"code":420034}}'))).toBe(420034)
  })

  it('reads only the root code when both shapes are present', () => {
    expect(readDaaStatusCode(bytes('{"code":420031,"status":{"code":420034}}'))).toBe(420031)
    expect(readDaaStatusCode(bytes('{"code":499999,"status":{"code":420031}}'))).toBe(499999)
    expect(
      readDaaStatusCode(bytes('{"code":"DEVICE_AUTHORIZATION_EXPIRED","status":{"code":420031}}')),
    ).toBe('DEVICE_AUTHORIZATION_EXPIRED')
  })

  it('does not fall back to status.code when a present root code is unreadable', () => {
    for (const root of ['{"nested":1}', '[420031]', '""', 'true', 'false', '1e999']) {
      expect(readDaaStatusCode(bytes(`{"code":${root},"status":{"code":420031}}`))).toBeNull()
    }
  })

  it('hands a quoted numeric code back as the number', () => {
    expect(readDaaStatusCode(bytes('{"code":"420034"}'))).toBe(420034)
  })

  it('is null for a body with no readable code', () => {
    expect(readDaaStatusCode(bytes('{"message":"no code"}'))).toBeNull()
    expect(readDaaStatusCode(bytes('{"code":[420034]}'))).toBeNull()
    expect(readDaaStatusCode(bytes('{"code":""}'))).toBeNull()
    expect(readDaaStatusCode(bytes('<html>bad gateway</html>'))).toBeNull()
    expect(readDaaStatusCode(null)).toBeNull()
  })
})

describe('the status-code table', () => {
  it('carries the numbers DAA sends', () => {
    expect(DAA_STATUS_CODES).toEqual({
      DEVICE_AUTHORIZATION_INVALID: 420031,
      IDEMPOTENCY_KEY_REUSED: 420034,
      DEVICE_AUTHORIZATION_REQUEST_MISMATCH: 420036,
      AUTH_KEY_BINDING_CONFLICT: 420038,
      LOGIN_REQUEST_CONSUMED: 420039,
      DEVICE_AUTHORIZATION_REPLAYED: 420043,
    })
    expect(Object.isFrozen(DAA_STATUS_CODES)).toBe(true)
  })

  it('matches the numeric code only', () => {
    expect(isDaaStatus(420034, 'IDEMPOTENCY_KEY_REUSED')).toBe(true)
    expect(isDaaStatus('IDEMPOTENCY_KEY_REUSED', 'IDEMPOTENCY_KEY_REUSED')).toBe(false)
    expect(isDaaStatus(420035, 'IDEMPOTENCY_KEY_REUSED')).toBe(false)
    // A decimal string is turned into the number by readDaaStatusCode, not here.
    expect(isDaaStatus('420034', 'IDEMPOTENCY_KEY_REUSED')).toBe(false)
    expect(isDaaStatus(null, 'IDEMPOTENCY_KEY_REUSED')).toBe(false)
  })

  it('matches no table row from any name string, including the row’s own name', () => {
    for (const code of NAME_STRINGS) {
      for (const name of Object.keys(DAA_STATUS_CODES) as DaaStatusName[]) {
        expect(isDaaStatus(code, name)).toBe(false)
      }
    }
  })
})

describe.each(SIGNED_WRITES)('%s with a real DAA error body', (_name, signedCall) => {
  it('maps 409 / 420034 to idempotency_conflict with the request’s own key', async () => {
    const { transport, call } = await signedCall([failure(409, 420034)])

    expect(await detailOf(call)).toEqual({
      kind: 'idempotency_conflict',
      idempotencyKey: IDEMPOTENCY_KEY,
      correlationId: REQUEST_ID,
    })
    expect(transport.sent).toHaveLength(1)
  })

  it('keeps 400 / 420034 an api failure: idempotency_conflict needs the documented 409', async () => {
    // What DAA's transfer and withdrawal create routes send.
    const { transport, call } = await signedCall([failure(400, 420034)])

    expect(await detailOf(call)).toEqual({
      kind: 'api',
      httpStatus: 400,
      daaStatusCode: 420034,
      retryable: false,
    })
    expect(transport.sent).toHaveLength(1)
  })

  it('maps 409 / 420043 (replayed) to contract_violation without retrying', async () => {
    const { transport, call } = await signedCall([failure(409, 420043)])

    expect(await detailOf(call)).toEqual({ kind: 'contract_violation', correlationId: REQUEST_ID })
    expect(transport.sent).toHaveLength(1)
  })
})

describe.each(SIGNED_CALLS)('%s device-authorization failures', (_name, signedCall) => {
  it.each([
    [401, 420031],
    [400, 420031],
    [403, 420036],
  ])('maps %i / %i to contract_violation without retrying', async (status, code) => {
    const { transport, call } = await signedCall([failure(status, code)])

    expect(await detailOf(call)).toEqual({ kind: 'contract_violation', correlationId: REQUEST_ID })
    expect(transport.sent).toHaveLength(1)
  })

  it('keeps a code the signed mapping does not classify observable as api', async () => {
    // LOGIN_REQUEST_CONSUMED: a real DAA code that only the login calls map.
    const { transport, call } = await signedCall([failure(409, 420039)])

    expect(await detailOf(call)).toEqual({
      kind: 'api',
      httpStatus: 409,
      daaStatusCode: 420039,
      retryable: false,
    })
    expect(transport.sent).toHaveLength(1)
  })
})

describe('refreshContext with a real DAA error body', () => {
  it('has no key to recover from a bodyless GET, so 409 / 420034 stays an api failure', async () => {
    const { call } = await REFRESH_CONTEXT([failure(409, 420034)])

    expect(await detailOf(call)).toEqual({
      kind: 'api',
      httpStatus: 409,
      daaStatusCode: 420034,
      retryable: false,
    })
  })
})

describe('an unsigned call with a real DAA error body', () => {
  const DEPOSIT_KEY = '44444444-4444-4444-8444-444444444444'

  async function createDepositAddress(response: DaaHttpResponse): Promise<DaaSdkError> {
    const transport = new SequenceTransport([response])
    const signing = signingFor(await registeredAuthKey(), AUTH_KEY_ID)
    return detailOf(
      createDaaUserClient(transport, 'production', signing).depositAddresses.create({
        idempotencyKey: DEPOSIT_KEY,
        accountId: 'account-1',
        currency: 'USD',
        chain: 'ETH',
      }),
    )
  }

  it('maps 409 + IDEMPOTENCY_KEY_REUSED on deposit-address create to idempotency_conflict with the request key', async () => {
    expect(await createDepositAddress(failure(409, 420034))).toEqual({
      kind: 'idempotency_conflict',
      idempotencyKey: DEPOSIT_KEY,
      correlationId: REQUEST_ID,
    })
  })

  it('reads the decimal-string and status.code forms of 420034 on deposit-address create', async () => {
    for (const body of ['{"code":"420034"}', '{"status":{"code":420034}}']) {
      expect(await createDepositAddress(failureBody(409, body))).toEqual({
        kind: 'idempotency_conflict',
        idempotencyKey: DEPOSIT_KEY,
        correlationId: REQUEST_ID,
      })
    }
  })

  it('keeps 420034 on another status as an api failure carrying the numeric code', async () => {
    expect(await createDepositAddress(failure(400, 420034))).toEqual({
      kind: 'api',
      httpStatus: 400,
      daaStatusCode: 420034,
      retryable: false,
    })
  })

  it('keeps another 409 on deposit-address create as an api failure', async () => {
    expect(await createDepositAddress(failure(409, 2))).toEqual({
      kind: 'api',
      httpStatus: 409,
      daaStatusCode: 2,
      retryable: false,
    })
    expect(
      await createDepositAddress(failureBody(409, '{"code":"IDEMPOTENCY_KEY_REUSED"}')),
    ).toEqual({
      kind: 'api',
      httpStatus: 409,
      daaStatusCode: 'IDEMPOTENCY_KEY_REUSED',
      retryable: false,
    })
    expect(
      await createDepositAddress(failureBody(409, '{"code":499999,"status":{"code":420034}}')),
    ).toEqual({
      kind: 'api',
      httpStatus: 409,
      daaStatusCode: 499999,
      retryable: false,
    })
  })
})

describe.each(SIGNED_CALLS)('%s: the numeric-code matching rule', (_name, call) => {
  it.each([
    ['a decimal string', '{"code":"420031"}'],
    ['status.code when the root code is absent', '{"status":{"code":420031}}'],
    ['status.code when the root code is null', '{"code":null,"status":{"code":420031}}'],
  ])('classifies %s for 420031 as contract_violation', async (_label, body) => {
    const { transport, call: pending } = await call([failureBody(400, body)])

    expect(await detailOf(pending)).toEqual({
      kind: 'contract_violation',
      correlationId: REQUEST_ID,
    })
    expect(transport.sent).toHaveLength(1)
  })

  it.each(NAME_STRINGS)('classifies the name string %s as api and sends once', async (name) => {
    const { transport, call: pending } = await call([
      failureBody(400, `{"code":"${name}"}`),
      failureBody(400, `{"code":"${name}"}`),
    ])

    expect(await detailOf(pending)).toEqual({
      kind: 'api',
      httpStatus: 400,
      daaStatusCode: name,
      retryable: false,
    })
    expect(transport.sent).toHaveLength(1)
  })

  it('classifies a code that is not in the table as api', async () => {
    const { call: pending } = await call([failure(400, 499999)])

    expect(await detailOf(pending)).toEqual({
      kind: 'api',
      httpStatus: 400,
      daaStatusCode: 499999,
      retryable: false,
    })
  })

  it.each([
    ['an unknown numeric', '499999', 499999],
    ['an uncoded name as', '"DEVICE_AUTHORIZATION_EXPIRED"', 'DEVICE_AUTHORIZATION_EXPIRED'],
    ['a coded name as', '"DEVICE_AUTHORIZATION_INVALID"', 'DEVICE_AUTHORIZATION_INVALID'],
  ])(
    'classifies %s root code as api even when status.code is 420031',
    async (_label, root, daaStatusCode) => {
      const { call: pending } = await call([
        failureBody(400, `{"code":${root},"status":{"code":420031}}`),
      ])

      expect(await detailOf(pending)).toEqual({
        kind: 'api',
        httpStatus: 400,
        daaStatusCode,
        retryable: false,
      })
    },
  )

  it.each(['""', 'true', '{"nested":1}'])(
    'classifies a present but unreadable root code %s as api even when status.code is 420031',
    async (root) => {
      const { call: pending } = await call([
        failureBody(400, `{"code":${root},"status":{"code":420031}}`),
      ])

      expect(await detailOf(pending)).toEqual({ kind: 'api', httpStatus: 400, retryable: false })
    },
  )
})

describe.each(SIGNED_WRITES)('%s: 420034 in each accepted shape', (_name, signedCall) => {
  it.each([
    ['a decimal string', '{"code":"420034"}'],
    ['status.code', '{"status":{"code":420034}}'],
  ])('maps 409 with %s to idempotency_conflict', async (_label, body) => {
    const { call } = await signedCall([failureBody(409, body)])

    expect(await detailOf(call)).toEqual({
      kind: 'idempotency_conflict',
      idempotencyKey: IDEMPOTENCY_KEY,
      correlationId: REQUEST_ID,
    })
  })

  it.each([
    ['at the root', '{"code":"IDEMPOTENCY_KEY_REUSED"}'],
    ['at status.code', '{"status":{"code":"IDEMPOTENCY_KEY_REUSED"}}'],
  ])(
    'keeps 409 with the name string IDEMPOTENCY_KEY_REUSED %s an api failure and sends once',
    async (_label, body) => {
      const { transport, call } = await signedCall([failureBody(409, body), failureBody(409, body)])

      expect(await detailOf(call)).toEqual({
        kind: 'api',
        httpStatus: 409,
        daaStatusCode: 'IDEMPOTENCY_KEY_REUSED',
        retryable: false,
      })
      expect(transport.sent).toHaveLength(1)
    },
  )
})

describe('the login mapping under the numeric-code matching rule', () => {
  const LOGIN_KEY = '66666666-6666-4666-8666-666666666666'

  it.each([
    ['a decimal string', '{"code":"420034"}'],
    ['status.code', '{"status":{"code":420034}}'],
  ])('maps 409 with %s for 420034 to idempotency_conflict', (_label, body) => {
    expect(loginStepFailure(failureBody(409, body), LOGIN_KEY)?.detail).toEqual({
      kind: 'idempotency_conflict',
      idempotencyKey: LOGIN_KEY,
      correlationId: REQUEST_ID,
    })
  })

  it.each([
    ['a decimal string', '{"code":"420039"}'],
    ['status.code', '{"status":{"code":420039}}'],
  ])('maps %s for 420039 to contract_violation', (_label, body) => {
    expect(loginStepFailure(failureBody(409, body), LOGIN_KEY)?.detail).toEqual({
      kind: 'contract_violation',
      correlationId: REQUEST_ID,
    })
  })

  it.each(NAME_STRINGS)('leaves 409 with the name string %s to the api fallback', (name) => {
    expect(loginStepFailure(failureBody(409, `{"code":"${name}"}`), LOGIN_KEY)).toBeNull()
    expect(
      loginStepFailure(failureBody(409, `{"status":{"code":"${name}"}}`), LOGIN_KEY),
    ).toBeNull()
  })

  it('leaves an unknown root code to the api fallback even when status.code is 420034', () => {
    expect(
      loginStepFailure(failureBody(409, '{"code":499999,"status":{"code":420034}}'), LOGIN_KEY),
    ).toBeNull()
  })
})
