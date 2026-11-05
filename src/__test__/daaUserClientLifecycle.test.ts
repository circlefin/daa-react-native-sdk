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
import { DEVICE_AUTHORIZATION_HEADER } from '../auth/deviceAuthorization'
import { fromBase64Url } from '../crypto/base64url'
import { isDaaError } from '../errors'
import type { DaaSdkError } from '../errors'
import type { CreateAccountRequest } from '../models/CreateAccountRequest'
import type { CreateTransferRequest } from '../models/CreateTransferRequest'
import type { CreateWithdrawalRequest } from '../models/CreateWithdrawalRequest'
import type { DaaHttpRequest, DaaHttpResponse, DaaTransport } from '../transport/DaaTransport'
import { registeredAuthKey, signingFor, unregisteredAuthKey } from './userClientSigning'

/**
 * `DaaUserClient.refreshContext` and `.close()` — the two lifecycle methods.
 * Mirrors `withdrawalsCreate.test.ts`'s
 * discipline: literal wire facts, not a comparison against the constant the
 * production code reads.
 */

const CONTEXT_PATH = '/v1/accounts/auth/context'
const AUTH_KEY_ID = '11111111-1111-4111-8111-111111111111'
const OWNER_BINDING_ID = '22222222-2222-4222-a222-222222222222'
const RESOLVED_AT = '2026-01-01T00:00:00Z'

/** A complete `DeviceContext`: every field the service guarantees. */
const DEVICE_CONTEXT_PAYLOAD =
  '{"deviceCredentialStatus":"active",' +
  `"ownerBindingId":"${OWNER_BINDING_ID}",` +
  `"authKeyId":"${AUTH_KEY_ID}",` +
  `"resolvedAt":"${RESOLVED_AT}"}`

class RecordingTransport implements DaaTransport {
  readonly sent: DaaHttpRequest[] = []

  constructor(private readonly response: DaaHttpResponse) {}

  async send(request: DaaHttpRequest): Promise<DaaHttpResponse> {
    this.sent.push(request)
    return this.response
  }
}

function bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text)
}

function envelope(payload: string): Uint8Array {
  return bytes(`{"data":${payload}}`)
}

function claimsOf(request: DaaHttpRequest): Record<string, unknown> {
  const compact = request.headers[DEVICE_AUTHORIZATION_HEADER]
  if (compact === undefined) {
    throw new Error('missing device authorization')
  }
  return JSON.parse(new TextDecoder().decode(fromBase64Url(compact.split('.')[1] ?? '')))
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

async function refreshableClient(payload = DEVICE_CONTEXT_PAYLOAD, status = 200) {
  const transport = new RecordingTransport({
    status,
    headers: { 'X-Request-Id': 'req-context' },
    bodyBytes: envelope(payload),
  })
  const signing = signingFor(await registeredAuthKey(), AUTH_KEY_ID)
  return {
    user: createDaaUserClient(transport, 'production', signing),
    transport,
    signing,
  }
}

describe('refreshContext', () => {
  it('signs a bodyless GET to the registry canonical path and decodes the DeviceContext', async () => {
    const { user, transport } = await refreshableClient()

    const context = await user.refreshContext()

    expect(transport.sent).toHaveLength(1)
    const request = transport.sent[0]
    if (request === undefined) throw new Error('no request was sent')
    expect(request.method).toBe('GET')
    expect(request.path).toBe(CONTEXT_PATH)
    expect(request.query).toBeNull()
    expect(request.bodyBytes).toBeNull()
    expect(claimsOf(request)).toMatchObject({
      canonical_path: CONTEXT_PATH,
      method: 'GET',
      discriminator: 'get_device_context',
      schema_version: 1,
      aud: 'circle-digital-asset-accounts',
    })
    expect(claimsOf(request)).not.toHaveProperty('idempotency_key')

    expect(context).toEqual({
      deviceCredentialStatus: 'active',
      ownerBindingId: OWNER_BINDING_ID,
      authKeyId: AUTH_KEY_ID,
      resolvedAt: RESOLVED_AT,
    })
  })

  it('fails closed while the AuthKey is not yet registered, before sending anything', async () => {
    const transport = new RecordingTransport({ status: 200, headers: {}, bodyBytes: null })
    const authKey = await unregisteredAuthKey()
    expect(authKey.resolution()).toBe('created')
    const user = createDaaUserClient(transport, 'production', signingFor(authKey, AUTH_KEY_ID))

    expect(await detailOf(user.refreshContext())).toEqual({ kind: 'contract_violation' })
    expect(transport.sent).toHaveLength(0)
  })

  it('accepts only the documented 200', async () => {
    for (const status of [201, 204, 299]) {
      const { user } = await refreshableClient(DEVICE_CONTEXT_PAYLOAD, status)
      const detail = await detailOf(user.refreshContext())
      expect(detail.kind).toBe('api')
      if (detail.kind === 'api') expect(detail.httpStatus).toBe(status)
    }
  })

  it('maps a malformed data envelope to a contract violation', async () => {
    const { user } = await refreshableClient('{}')
    expect((await detailOf(user.refreshContext())).kind).toBe('contract_violation')
  })
})

describe('close', () => {
  it('closes further refreshContext calls without resolving the AuthKey or touching the transport', async () => {
    const { user, transport, signing } = await refreshableClient()

    user.close()

    expect(await detailOf(user.refreshContext())).toEqual({ kind: 'contract_violation' })
    expect(transport.sent).toHaveLength(0)
    expect(signing.resolutions()).toBe(0)
  })

  it('closes signed writes on accounts, transfers, and withdrawals', async () => {
    const transport = new RecordingTransport({ status: 201, headers: {}, bodyBytes: null })
    const signing = signingFor(await registeredAuthKey(), AUTH_KEY_ID)
    const user = createDaaUserClient(transport, 'production', signing)

    const accountRequest: CreateAccountRequest = {
      idempotencyKey: '33333333-3333-4333-a333-333333333333',
      clientEntityId: '77777777-7777-4777-8777-777777777777',
      custodyType: 'self',
      type: 'third_party',
      purpose: 'custody',
      description: 'test account',
      blockchain: 'ARC',
    }
    const transferRequest: CreateTransferRequest = {
      idempotencyKey: '44444444-4444-4444-8444-444444444444',
      destination: { type: 'account', id: 'acct-dst' },
      amount: { amount: '10.00', currency: 'USD' },
    }
    const withdrawalRequest: CreateWithdrawalRequest = {
      idempotencyKey: '55555555-5555-4555-8555-555555555555',
      destination: { type: 'wire', id: '66666666-6666-4666-8666-666666666666' },
      amount: { amount: '10.00', currency: 'USD' },
    }

    user.close()

    expect(await detailOf(user.accounts.create(accountRequest))).toEqual({
      kind: 'contract_violation',
    })
    expect(await detailOf(user.transfers.create(transferRequest))).toEqual({
      kind: 'contract_violation',
    })
    expect(await detailOf(user.withdrawals.create(withdrawalRequest))).toEqual({
      kind: 'contract_violation',
    })
    expect(transport.sent).toHaveLength(0)
    expect(signing.resolutions()).toBe(0)
  })

  it('does not sign with an AuthKey that was resolved before close', async () => {
    const transport = new RecordingTransport({
      status: 200,
      headers: {},
      bodyBytes: envelope(DEVICE_CONTEXT_PAYLOAD),
    })
    const authKey = await registeredAuthKey()
    let close: () => void = () => {}
    const user = createDaaUserClient(transport, 'production', {
      authKeyId: AUTH_KEY_ID,
      resolveAuthKey: async () => {
        close()
        return authKey
      },
    })
    close = () => user.close()

    expect(await detailOf(user.refreshContext())).toEqual({ kind: 'contract_violation' })
    expect(transport.sent).toHaveLength(0)
  })

  it('gates unsigned reads after close', async () => {
    const transport = new RecordingTransport({
      status: 200,
      headers: {},
      bodyBytes: envelope(
        '{"accountId":"acct-1","balances":[{"amount":"0.00","currency":"USD"}],' +
          '"entityId":"entity-1","purpose":"custody","status":"active","type":"first_party"}',
      ),
    })
    const signing = signingFor(await registeredAuthKey(), AUTH_KEY_ID)
    const user = createDaaUserClient(transport, 'production', signing)

    user.close()

    expect(await detailOf(user.accounts.get('acct-1'))).toEqual({
      kind: 'contract_violation',
    })
    expect(transport.sent).toHaveLength(0)
  })

  it('is idempotent', async () => {
    const { user, transport } = await refreshableClient()

    user.close()
    user.close()

    expect(await detailOf(user.refreshContext())).toEqual({ kind: 'contract_violation' })
    expect(transport.sent).toHaveLength(0)
  })
})
