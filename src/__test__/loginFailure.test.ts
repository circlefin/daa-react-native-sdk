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

import { AuthClient } from '../api/AuthClient'
import { webCryptoRegistrationFlowKeyProvider } from '../auth/RegistrationFlowKey'
import { isDaaError } from '../errors'
import type { DaaSdkError } from '../errors'
import { InMemorySecureKeyStore } from '../securekey/InMemorySecureKey'
import type { DaaHttpRequest, DaaHttpResponse, DaaTransport } from '../transport/DaaTransport'

/**
 * The login calls' failure mapping, with DAA's real error body.
 *
 * DAA returns `409` for three different codes on the login path:
 * `IDEMPOTENCY_KEY_REUSED` (`420034`), `LOGIN_REQUEST_CONSUMED` (`420039`) and
 * `AUTH_KEY_BINDING_CONFLICT` (`420038`). Only the first is
 * `idempotency_conflict`. Each code is a literal here, so a wrong number in
 * the table fails these tests.
 */

class ScriptedTransport implements DaaTransport {
  readonly sent: DaaHttpRequest[] = []

  constructor(private readonly responses: DaaHttpResponse[]) {}

  async send(request: DaaHttpRequest): Promise<DaaHttpResponse> {
    this.sent.push(request)
    const response = this.responses[this.sent.length - 1]
    if (response === undefined) {
      throw new Error(`unexpected request ${request.method} ${request.path}`)
    }
    return response
  }
}

const LOGIN_REQUEST_ID = '3f1a2b4c-5d6e-4f70-8192-a3b4c5d6e7f8'
const CLIENT_ENTITY_ID = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
const NONCE = 'n'.repeat(48)
const STATE = 's'.repeat(48)
const EXPIRES_AT = '2026-08-26T12:00:00Z'
const HANDLE = 'h'.repeat(32)
const REQUEST_ID = 'req-login-1'

const PREPARED = `{"loginRequestId":"${LOGIN_REQUEST_ID}","oidcNonce":"${NONCE}","oidcState":"${STATE}","expiresAt":"${EXPIRES_AT}"}`
const SESSION = `{"registrationHandle":"${HANDLE}","clientEntityId":"${CLIENT_ENTITY_ID}","expiresAt":"${EXPIRES_AT}"}`

function bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text)
}

function ok(status: number, payload: string): DaaHttpResponse {
  return { status, headers: { 'X-Request-Id': 'req-ok' }, bodyBytes: bytes(`{"data":${payload}}`) }
}

/** The error body DAA actually sends. */
function failure(status: number, code: number | string): DaaHttpResponse {
  return {
    status,
    headers: { 'X-Request-Id': REQUEST_ID },
    bodyBytes: bytes(
      `{"code":${JSON.stringify(code)},"message":"internal detail","externalMessage":"The request was rejected"}`,
    ),
  }
}

function client(responses: DaaHttpResponse[]): { auth: AuthClient; transport: ScriptedTransport } {
  const transport = new ScriptedTransport(responses)
  const auth = new AuthClient({
    transport,
    registrationFlowKeys: webCryptoRegistrationFlowKeyProvider(),
    secureKeys: new InMemorySecureKeyStore(),
    identity: { appId: 'app-123', environment: 'sandbox' },
  })
  return { auth, transport }
}

function sentKey(transport: ScriptedTransport, index: number): unknown {
  const request = transport.sent[index]
  if (request === undefined || request.bodyBytes === null) {
    throw new Error('expected a request with a body')
  }
  return (JSON.parse(new TextDecoder().decode(request.bodyBytes)) as { idempotencyKey: unknown })
    .idempotencyKey
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

type Step = Readonly<{
  name: string
  index: number
  run: (
    failed: DaaHttpResponse,
  ) => Promise<{ call: Promise<unknown>; transport: ScriptedTransport }>
}>

const STEPS: readonly Step[] = [
  {
    name: 'Prepare',
    index: 0,
    run: async (failed) => {
      const { auth, transport } = client([failed])
      return { call: auth.prepareSocialLogin({ provider: 'GOOGLE' }), transport }
    },
  },
  {
    name: 'Social Session',
    index: 1,
    run: async (failed) => {
      const { auth, transport } = client([ok(201, PREPARED), failed])
      const prepared = await auth.prepareSocialLogin({ provider: 'GOOGLE' })
      return {
        call: prepared.completeSocialSession({
          idToken: 'ID_TOKEN_MARKER',
          clientEntityId: CLIENT_ENTITY_ID,
        }),
        transport,
      }
    },
  },
  {
    name: 'Device Registration Complete',
    index: 2,
    run: async (failed) => {
      const { auth, transport } = client([ok(201, PREPARED), ok(200, SESSION), failed])
      const prepared = await auth.prepareSocialLogin({ provider: 'GOOGLE' })
      const pending = await prepared.completeSocialSession({
        idToken: 'ID_TOKEN_MARKER',
        clientEntityId: CLIENT_ENTITY_ID,
      })
      return { call: pending.complete(), transport }
    },
  },
]

describe.each(STEPS)('$name failure mapping', ({ index, run }) => {
  it('maps 409 with IDEMPOTENCY_KEY_REUSED (420034) to idempotency_conflict with the key it sent', async () => {
    const { call, transport } = await run(failure(409, 420034))
    const detail = await detailOf(call)

    expect(detail).toEqual({
      kind: 'idempotency_conflict',
      idempotencyKey: sentKey(transport, index),
      correlationId: REQUEST_ID,
    })
    expect(transport.sent).toHaveLength(index + 1)
  })

  it.each(['IDEMPOTENCY_KEY_REUSED', 'LOGIN_REQUEST_CONSUMED'])(
    'keeps 409 with the name string %s a non-retryable api failure',
    async (name) => {
      const { call, transport } = await run(failure(409, name))

      expect(await detailOf(call)).toEqual({
        kind: 'api',
        httpStatus: 409,
        daaStatusCode: name,
        retryable: false,
      })
      expect(transport.sent).toHaveLength(index + 1)
    },
  )

  it('maps 409 with LOGIN_REQUEST_CONSUMED (420039) to contract_violation with the correlation id', async () => {
    const { call, transport } = await run(failure(409, 420039))

    expect(await detailOf(call)).toEqual({ kind: 'contract_violation', correlationId: REQUEST_ID })
    expect(transport.sent).toHaveLength(index + 1)
  })

  it('maps 409 with AUTH_KEY_BINDING_CONFLICT (420038) to a non-retryable api failure', async () => {
    const { call } = await run(failure(409, 420038))

    expect(await detailOf(call)).toEqual({
      kind: 'api',
      httpStatus: 409,
      daaStatusCode: 420038,
      retryable: false,
    })
  })

  it('does not treat a 409 without a classified code as idempotency_conflict', async () => {
    const { call } = await run({ status: 409, headers: {}, bodyBytes: null })

    expect(await detailOf(call)).toEqual({ kind: 'api', httpStatus: 409, retryable: false })
  })

  it('does not treat 420034 on another status as idempotency_conflict', async () => {
    const { call } = await run(failure(400, 420034))

    expect(await detailOf(call)).toEqual({
      kind: 'api',
      httpStatus: 400,
      daaStatusCode: 420034,
      retryable: false,
    })
  })

  it('maps 410 to login_request_expired', async () => {
    const { call } = await run(failure(410, 420035))

    expect(await detailOf(call)).toEqual({ kind: 'login_request_expired' })
  })
})
