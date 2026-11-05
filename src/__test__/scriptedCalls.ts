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

// Every SDK call that turns a DAA response into an error, driven through the
// real clients with one response scripted to fail.
//
// The tests that sweep the error paths (the request id, the service's own error
// bodies, no secret in an error) share this table, so a call added here is
// swept by all of them.
//
// Not a test file — Jest's `testMatch` is `**/__test__/**/*.test.ts`, so this
// module is only ever imported, never collected.

import { AuthClient } from '../api/AuthClient'
import { createDaaUserClient } from '../api/DaaUserClient'
import { webCryptoRegistrationFlowKeyProvider } from '../auth/RegistrationFlowKey'
import { isDaaError, type DaaError } from '../errors'
import { InMemorySecureKeyStore } from '../securekey/InMemorySecureKey'
import type { DaaHttpRequest, DaaHttpResponse, DaaTransport } from '../transport/DaaTransport'
import { registeredAuthKey, signingFor } from './userClientSigning'

/**
 * The shape of `X-Request-Id` in a Circle test environment: 32 lowercase hex
 * characters. Not a captured value.
 */
export const REQUEST_ID = '694b122b43d1b62dc75be5c6252f4de1'

export const IDEMPOTENCY_KEY = '22222222-2222-4222-a222-222222222222'
export const CLIENT_ENTITY_ID = '33333333-3333-4333-b333-333333333333'
const AUTH_KEY_ID = '11111111-1111-4111-8111-111111111111'
const DESTINATION_ID = '55555555-5555-4555-8555-555555555555'
const ACCOUNT_ID = '66666666-6666-4666-8666-666666666666'
const LOGIN_REQUEST_ID = '3f1a2b4c-5d6e-4f70-8192-a3b4c5d6e7f8'
export const EXPIRES_AT = '2026-08-26T12:00:00Z'

/** A provider ID token shaped like a JWT, so a leak would also match `eyJ`. */
export const ID_TOKEN =
  'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0LWlkLXRva2VuIn0.dGVzdC1zaWduYXR1cmU'
/** Distinctive enough that a substring match can only be this value. */
export const REGISTRATION_HANDLE = 'test-registration-handle-7f3c9e1b2a'

const PREPARED = `{"loginRequestId":"${LOGIN_REQUEST_ID}","oidcNonce":"${'n'.repeat(48)}","oidcState":"${'s'.repeat(48)}","expiresAt":"${EXPIRES_AT}"}`
const SESSION = `{"registrationHandle":"${REGISTRATION_HANDLE}","clientEntityId":"${CLIENT_ENTITY_ID}","expiresAt":"${EXPIRES_AT}"}`

export function bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text)
}

/** A DAA error body in the shape the service sends: `{"code":…,"message":…}`. */
export function serviceError(
  status: number,
  code: number,
  message: string,
  headers: Readonly<Record<string, string>> = { 'X-Request-Id': REQUEST_ID },
): DaaHttpResponse {
  return { status, headers, bodyBytes: bytes(JSON.stringify({ code, message })) }
}

function ok(status: number, payload: string): DaaHttpResponse {
  return { status, headers: { 'X-Request-Id': 'req-ok' }, bodyBytes: bytes(`{"data":${payload}}`) }
}

/** Builds the failing response, optionally from the request it answers. */
export type Responder = (request: DaaHttpRequest) => DaaHttpResponse

/** Records every request; the scripted step answers with the responder. */
export class ScriptedTransport implements DaaTransport {
  readonly sent: DaaHttpRequest[] = []

  constructor(
    private readonly before: readonly DaaHttpResponse[],
    private readonly respond: Responder,
  ) {}

  async send(request: DaaHttpRequest): Promise<DaaHttpResponse> {
    this.sent.push(request)
    const index = this.sent.length - 1
    if (index < this.before.length) {
      return this.before[index] as DaaHttpResponse
    }
    if (index === this.before.length) {
      return this.respond(request)
    }
    throw new Error(`unexpected request ${request.method} ${request.path}`)
  }
}

export type ScriptedCall = Readonly<{
  name: string
  /** `login` for the three ceremony calls, `user` for a `DaaUserClient` call. */
  surface: 'login' | 'user'
  /** The documented success status, for a malformed-success case. */
  successStatus: number
  /** Whether the request carries an idempotency key (`idempotency_conflict`). */
  idempotent: boolean
  run: (respond: Responder) => Promise<{ call: Promise<unknown>; transport: ScriptedTransport }>
}>

function loginClient(transport: DaaTransport): AuthClient {
  return new AuthClient({
    transport,
    registrationFlowKeys: webCryptoRegistrationFlowKeyProvider(),
    secureKeys: new InMemorySecureKeyStore(),
    identity: { appId: 'app-123', environment: 'sandbox' },
  })
}

async function userCall(
  respond: Responder,
  invoke: (user: ReturnType<typeof createDaaUserClient>) => Promise<unknown>,
) {
  const transport = new ScriptedTransport([], respond)
  const signing = signingFor(await registeredAuthKey(), AUTH_KEY_ID)
  return { transport, call: invoke(createDaaUserClient(transport, 'production', signing)) }
}

export const LOGIN_CALLS: readonly ScriptedCall[] = [
  {
    name: 'Prepare',
    surface: 'login',
    successStatus: 201,
    idempotent: true,
    run: async (respond) => {
      const transport = new ScriptedTransport([], respond)
      return { transport, call: loginClient(transport).prepareSocialLogin({ provider: 'GOOGLE' }) }
    },
  },
  {
    name: 'Social Session',
    surface: 'login',
    successStatus: 200,
    idempotent: true,
    run: async (respond) => {
      const transport = new ScriptedTransport([ok(201, PREPARED)], respond)
      const prepared = await loginClient(transport).prepareSocialLogin({ provider: 'GOOGLE' })
      return {
        transport,
        call: prepared.completeSocialSession({
          idToken: ID_TOKEN,
          clientEntityId: CLIENT_ENTITY_ID,
        }),
      }
    },
  },
  {
    name: 'Device Registration Complete',
    surface: 'login',
    successStatus: 200,
    idempotent: true,
    run: async (respond) => {
      const transport = new ScriptedTransport([ok(201, PREPARED), ok(200, SESSION)], respond)
      const prepared = await loginClient(transport).prepareSocialLogin({ provider: 'GOOGLE' })
      const pending = await prepared.completeSocialSession({
        idToken: ID_TOKEN,
        clientEntityId: CLIENT_ENTITY_ID,
      })
      return { transport, call: pending.complete() }
    },
  },
]

export const SIGNED_CALLS: readonly ScriptedCall[] = [
  {
    name: 'accounts.create',
    surface: 'user',
    successStatus: 201,
    idempotent: true,
    run: (respond) =>
      userCall(respond, (user) =>
        user.accounts.create({
          idempotencyKey: IDEMPOTENCY_KEY,
          clientEntityId: CLIENT_ENTITY_ID,
          custodyType: 'self',
          type: 'third_party',
          purpose: 'custody',
          description: 'Primary',
          blockchain: 'ARC',
        }),
      ),
  },
  {
    name: 'transfers.create',
    surface: 'user',
    successStatus: 201,
    idempotent: true,
    run: (respond) =>
      userCall(respond, (user) =>
        user.transfers.create({
          idempotencyKey: IDEMPOTENCY_KEY,
          destination: { type: 'account', id: ACCOUNT_ID },
          amount: { amount: '10.25', currency: 'USD' },
        }),
      ),
  },
  {
    name: 'withdrawals.create',
    surface: 'user',
    successStatus: 201,
    idempotent: true,
    run: (respond) =>
      userCall(respond, (user) =>
        user.withdrawals.create({
          idempotencyKey: IDEMPOTENCY_KEY,
          destination: { type: 'wire', id: DESTINATION_ID },
          amount: { amount: '10.25', currency: 'USD' },
        }),
      ),
  },
  {
    name: 'refreshContext',
    surface: 'user',
    successStatus: 200,
    idempotent: false,
    run: (respond) => userCall(respond, (user) => user.refreshContext()),
  },
]

export const UNSIGNED_CALLS: readonly ScriptedCall[] = [
  {
    name: 'depositAddresses.create',
    surface: 'user',
    successStatus: 201,
    idempotent: true,
    run: (respond) =>
      userCall(respond, (user) =>
        user.depositAddresses.create({
          idempotencyKey: IDEMPOTENCY_KEY,
          accountId: ACCOUNT_ID,
          currency: 'USD',
          chain: 'ETH',
        }),
      ),
  },
  {
    name: 'accounts.get',
    surface: 'user',
    successStatus: 200,
    idempotent: false,
    run: (respond) => userCall(respond, (user) => user.accounts.get(ACCOUNT_ID)),
  },
]

export const ALL_CALLS: readonly ScriptedCall[] = [
  ...LOGIN_CALLS,
  ...SIGNED_CALLS,
  ...UNSIGNED_CALLS,
]

/** The `DaaError` the call failed with; anything else fails the test. */
export async function daaErrorOf(call: Promise<unknown>): Promise<DaaError> {
  try {
    await call
  } catch (err) {
    if (isDaaError(err)) {
      return err
    }
    throw err
  }
  throw new Error('expected the call to fail')
}
