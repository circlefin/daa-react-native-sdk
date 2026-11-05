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
import { toBase64Url } from '../crypto/base64url'
import type { DaaSdkError } from '../errors'
import type { DaaHttpResponse } from '../transport/DaaTransport'
import { generateReceiptSigningKey, trustAnchorFor } from './prepareReceiptSigning'
import {
  ALL_CALLS,
  bytes,
  CLIENT_ENTITY_ID,
  daaErrorOf,
  EXPIRES_AT,
  LOGIN_CALLS,
  REGISTRATION_HANDLE,
  REQUEST_ID,
  ScriptedTransport,
  serviceError,
  SIGNED_CALLS,
  type ScriptedCall,
} from './scriptedCalls'

/**
 * Every error the SDK builds from a DAA response names that response's
 * `X-Request-Id` in its message, whatever the kind.
 *
 * The request id is what lets support find the call server-side, and
 * `message` is what an application logs. A kind that drops it leaves a
 * developer with an error nobody can trace. The table is every kind a response
 * can produce on each call, so a new kind or a new call that forgets the id
 * fails here.
 */

type ErrorCase = Readonly<{
  label: string
  kind: DaaSdkError['kind']
  response: (call: ScriptedCall, headers: Readonly<Record<string, string>>) => DaaHttpResponse
  appliesTo: (call: ScriptedCall) => boolean
}>

const CORRELATED_KINDS = new Set<DaaSdkError['kind']>([
  'contract_violation',
  'idempotency_conflict',
])
const SIGNED = new Set(SIGNED_CALLS.map((call) => call.name))
const LOGIN = new Set(LOGIN_CALLS.map((call) => call.name))

const CASES: readonly ErrorCase[] = [
  {
    label: 'an unclassified 4xx',
    kind: 'api',
    response: (_call, headers) => serviceError(400, 420014, 'Insufficient balance', headers),
    appliesTo: () => true,
  },
  {
    label: 'a success status with a body that is not the contract',
    kind: 'contract_violation',
    response: (call, headers) => ({
      status: call.successStatus,
      headers,
      bodyBytes: bytes('{"data":{}}'),
    }),
    appliesTo: () => true,
  },
  {
    label: '410',
    kind: 'login_request_expired',
    response: (_call, headers) =>
      serviceError(410, 420035, 'The login request has expired', headers),
    appliesTo: (call) => LOGIN.has(call.name),
  },
  {
    label: '409 / 420034',
    kind: 'idempotency_conflict',
    response: (_call, headers) =>
      serviceError(
        409,
        420034,
        'The idempotency key was already used with a different request body',
        headers,
      ),
    appliesTo: (call) => call.idempotent,
  },
  {
    label: '409 / 420039',
    kind: 'contract_violation',
    response: (_call, headers) => serviceError(409, 420039, 'The login request was used', headers),
    appliesTo: (call) => LOGIN.has(call.name),
  },
  {
    label: '400 / 420031',
    kind: 'contract_violation',
    response: (_call, headers) =>
      serviceError(400, 420031, 'The device authorization is invalid', headers),
    appliesTo: (call) => SIGNED.has(call.name),
  },
  {
    label: '409 / 420043',
    kind: 'contract_violation',
    response: (_call, headers) =>
      serviceError(409, 420043, 'The device authorization was replayed', headers),
    appliesTo: (call) => SIGNED.has(call.name),
  },
]

const ROWS = ALL_CALLS.flatMap((call) =>
  CASES.filter((errorCase) => errorCase.appliesTo(call)).map(
    (errorCase) => [call.name, errorCase.label, call, errorCase] as const,
  ),
)

describe.each(ROWS)('%s, %s', (_name, _label, call, errorCase) => {
  it('names the request id in the message', async () => {
    const { call: pending } = await call.run(() =>
      errorCase.response(call, { 'X-Request-Id': REQUEST_ID }),
    )
    const err = await daaErrorOf(pending)

    expect(err.detail.kind).toBe(errorCase.kind)
    expect(err.message.endsWith(` (requestId=${REQUEST_ID})`)).toBe(true)
    // The two kinds that model a correlation id carry it on the detail too, for
    // a host that reports `err.detail` rather than the message.
    if (CORRELATED_KINDS.has(err.detail.kind)) {
      expect(err.detail).toHaveProperty('correlationId', REQUEST_ID)
    }
  })

  it('adds no request id when the response has none', async () => {
    const { call: pending } = await call.run(() => errorCase.response(call, {}))
    const err = await daaErrorOf(pending)

    expect(err.detail.kind).toBe(errorCase.kind)
    expect(err.message).not.toMatch(/requestId=/)
    expect(err.detail).not.toHaveProperty('correlationId')
  })
})

/**
 * Checks that run on a decoded success response: the Prepare receipt and the
 * Owner grant's flow-key binding. The failure is in that response, so it names
 * that response's request id too.
 */
describe('a check on a decoded response', () => {
  const PREPARED = {
    loginRequestId: '3f1a2b4c-5d6e-4f70-8192-a3b4c5d6e7f8',
    oidcNonce: 'n'.repeat(48),
    oidcState: 's'.repeat(48),
    expiresAt: EXPIRES_AT,
  }

  function prepared(receipt: unknown, headers: Readonly<Record<string, string>>): DaaHttpResponse {
    return {
      status: 201,
      headers,
      bodyBytes: bytes(JSON.stringify({ data: { ...PREPARED, prepareReceiptJws: receipt } })),
    }
  }

  async function prepareWithAnchor(response: DaaHttpResponse) {
    const transport = new ScriptedTransport([], () => response)
    const auth = new AuthClient({
      transport,
      environment: 'sandbox',
      prepareReceiptTrustAnchor: trustAnchorFor([await generateReceiptSigningKey()]),
    })
    return daaErrorOf(auth.prepareSocialLogin({ provider: 'GOOGLE' }))
  }

  it.each([
    ['a missing receipt', null],
    ['a malformed receipt', 'not-a-jws'],
  ])('names the request id when the Prepare response carries %s', async (_label, receipt) => {
    const err = await prepareWithAnchor(prepared(receipt, { 'X-Request-Id': REQUEST_ID }))

    expect(err.detail).toEqual({ kind: 'prepare_receipt_invalid' })
    expect(err.message.endsWith(` (requestId=${REQUEST_ID})`)).toBe(true)
  })

  it('adds no request id to a rejected receipt when the response has none', async () => {
    const err = await prepareWithAnchor(prepared(null, {}))

    expect(err.detail).toEqual({ kind: 'prepare_receipt_invalid' })
    expect(err.message).not.toMatch(/requestId=/)
  })

  it.each([
    ['with', { 'X-Request-Id': REQUEST_ID }],
    ['without', {}],
  ])(
    'carries the request id on an unbound Owner grant only %s the header',
    async (label, headers) => {
      const encode = (value: object) => toBase64Url(bytes(JSON.stringify(value)))
      const grant = `${encode({ alg: 'ES256' })}.${encode({
        registrationFlowKeyThumbprint: 'c'.repeat(43),
      })}.c2ln`
      const session = LOGIN_CALLS.find((call) => call.name === 'Social Session') as ScriptedCall
      const { call } = await session.run(() => ({
        status: 200,
        headers,
        bodyBytes: bytes(
          JSON.stringify({
            data: {
              registrationHandle: REGISTRATION_HANDLE,
              clientEntityId: CLIENT_ENTITY_ID,
              expiresAt: EXPIRES_AT,
              ownerGrant: grant,
            },
          }),
        ),
      }))
      const err = await daaErrorOf(call)

      if (label === 'with') {
        expect(err.detail).toEqual({ kind: 'contract_violation', correlationId: REQUEST_ID })
        expect(err.message.endsWith(` (requestId=${REQUEST_ID})`)).toBe(true)
      } else {
        expect(err.detail).toEqual({ kind: 'contract_violation' })
        expect(err.message).not.toMatch(/requestId=/)
      }
      expect(err.message).toMatch(/does not match the registration-flow key/)
    },
  )
})
