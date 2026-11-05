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
import { isDaaError } from '../errors'
import type { DaaSdkError } from '../errors'
import type { Money } from '../models/Money'
import type { DaaHttpRequest, DaaHttpResponse, DaaTransport } from '../transport/DaaTransport'

/**
 * The account read, end to end through the client: request shape, envelope,
 * decoding, and status mapping.
 */

class RecordingTransport implements DaaTransport {
  readonly sent: DaaHttpRequest[] = []

  constructor(private readonly response: DaaHttpResponse) {}

  async send(request: DaaHttpRequest): Promise<DaaHttpResponse> {
    this.sent.push(request)
    return this.response
  }
}

/** A complete account: every field the service guarantees, plus the custody type. */
const COMPLETE_ACCOUNT =
  '{"accountId":"acct-1","balances":[],"entityId":"e","purpose":"custody",' +
  '"status":"active","type":"first_party","custodyType":"self"}'

function bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text)
}

function envelope(payload: string): Uint8Array {
  return bytes(`{"data":${payload}}`)
}

function clientFor(response: Partial<DaaHttpResponse>): {
  accounts: ReturnType<typeof createDaaUserClient>['accounts']
  transport: RecordingTransport
} {
  const transport = new RecordingTransport({
    status: response.status ?? 200,
    headers: response.headers ?? {},
    bodyBytes: response.bodyBytes ?? null,
  })
  return { accounts: createDaaUserClient(transport, 'production', NO_SIGNING).accounts, transport }
}

function okClient(payload = COMPLETE_ACCOUNT) {
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
  it('reads an account over the public accounts path', async () => {
    const { accounts, transport } = okClient()

    const account = await accounts.get('acct-1')

    expect(transport.sent).toHaveLength(1)
    const sent = transport.sent[0] as DaaHttpRequest
    expect(sent.method).toBe('GET')
    expect(sent.path).toBe('/v1/accounts/acct-1')
    expect(sent.query).toBeNull()
    expect(sent.bodyBytes).toBeNull()
    expect(sent.headers).toEqual({})
    expect(account.accountId).toBe('acct-1')
    expect(account.custodyType).toEqual({ kind: 'self' })
  })

  /**
   * An `accountId` carrying a path separator would address a different operation
   * rather than fail: `/v1/accounts/acct-1/transfers` is a real sibling route. An
   * empty one addresses the collection instead of a member.
   */
  it('rejects an accountId that would address a different route', async () => {
    const { accounts, transport } = okClient()

    for (const bad of ['acct-1/transfers', 'acct-1/', '/acct-1', '', 'a/b/c']) {
      const detail = await detailOf(accounts.get(bad))
      expect(detail.kind).toBe('contract_violation')
    }
    expect(transport.sent).toHaveLength(0)
  })

  // Rejecting only a literal `/` is not enough. The native SDKs get a second
  // line of defence for free — their request type refuses anything outside the
  // RFC 3986 unreserved set — but `DaaTransport` is a consumer-implemented
  // interface, so nothing downstream here would catch an encoded separator.
  it('rejects an accountId carrying an encoded separator or other unsafe character', async () => {
    const { accounts, transport } = okClient()

    for (const bad of [
      'acct-1%2Ftransfers',
      'acct%2f1',
      'acct-1?x=1',
      'acct-1#frag',
      'acct 1',
      'acct-1\u0000',
      'acct-1\r\nX-Injected: 1',
      '.',
      '..',
      'acct/../transfers',
    ]) {
      const detail = await detailOf(accounts.get(bad))
      expect(detail.kind).toBe('contract_violation')
    }
    expect(transport.sent).toHaveLength(0)
  })

  it('accepts the unreserved characters a service-assigned id can use', async () => {
    for (const good of ['acct-1', 'ACCT_1', 'a.b~c', '0123456789']) {
      const { accounts, transport } = okClient()
      await accounts.get(good)
      expect(transport.sent[0]?.path).toBe(`/v1/accounts/${good}`)
    }
  })
})

describe('the success path', () => {
  it('accepts the documented 200 status', async () => {
    const { accounts } = clientFor({ status: 200, bodyBytes: envelope(COMPLETE_ACCOUNT) })
    expect((await accounts.get('acct-1')).accountId).toBe('acct-1')
  })

  /**
   * The payload sits under `data`. A body with it at the root — the shape the
   * OpenAPI schema documents — is malformed, not a value-less account.
   */
  it('rejects a body whose account sits at the root instead of the envelope', async () => {
    const { accounts } = clientFor({
      status: 200,
      headers: { 'X-Request-Id': 'req-2' },
      bodyBytes: bytes(COMPLETE_ACCOUNT),
    })

    expect(await detailOf(accounts.get('acct-1'))).toEqual({
      kind: 'contract_violation',
      correlationId: 'req-2',
    })
  })

  /** A `response` wrapper is not this SDK's envelope. */
  it('rejects a body wrapped in a response key instead of data', async () => {
    const { accounts } = clientFor({
      status: 200,
      bodyBytes: bytes(`{"response":${COMPLETE_ACCOUNT}}`),
    })

    expect((await detailOf(accounts.get('acct-1'))).kind).toBe('contract_violation')
  })

  /** An envelope present but empty is malformed — the wrapper is not optional on a 2xx. */
  it('rejects an empty envelope, an empty body, and no body at all', async () => {
    for (const bodyBytes of [bytes('{"data":null}'), bytes(''), null]) {
      const { accounts } = clientFor({ status: 200, bodyBytes })
      expect((await detailOf(accounts.get('acct-1'))).kind).toBe('contract_violation')
    }
  })

  /**
   * The invalid byte sits in a field the payload does **not** read, on purpose. In
   * a declared field, `JSON.parse` would reject the body on its own and the guard
   * would be redundant, and the test would pass whether or not the guard exists.
   * Lenient UTF-8 decoding replaces the bad sequence with U+FFFD,
   * which is a legal JSON string character, so nothing downstream would notice.
   */
  it('rejects a body with an invalid utf8 byte in a field it does not read', async () => {
    const head = bytes('{"data":{"accountId":"acct-1","undeclared":"')
    const tail = bytes(
      `","balances":[],"entityId":"e","purpose":"custody","status":"active","type":"first_party"}}`,
    )
    const body = new Uint8Array(head.length + 1 + tail.length)
    body.set(head, 0)
    body[head.length] = 0xff
    body.set(tail, head.length + 1)

    // Sanity: the same body with a valid byte decodes, or the assertion is vacuous.
    const valid = new Uint8Array(body)
    valid[head.length] = 0x41
    expect(
      (await clientFor({ status: 200, bodyBytes: valid }).accounts.get('acct-1')).accountId,
    ).toBe('acct-1')

    const { accounts } = clientFor({ status: 200, bodyBytes: body })
    expect((await detailOf(accounts.get('acct-1'))).kind).toBe('contract_violation')
  })

  /**
   * A `200` whose account is missing something the service guarantees must reach the
   * caller as a broken contract, not as a successful account with holes in it. The
   * correlation id has to survive, because it is the only thing that makes it
   * diagnosable server-side.
   */
  it('reports an account missing guaranteed fields as a broken contract with the correlation id', async () => {
    const payloads = [
      '{}',
      '{"accountId":"acct-1"}',
      '{"accountId":"acct-1","balances":[],"entityId":"e","purpose":"custody"}',
      // A guaranteed money amount the SDK cannot read is the same defect.
      '{"accountId":"acct-1","balances":[{"amount":"nope","currency":"USD"}],' +
        '"entityId":"e","purpose":"custody","status":"active","type":"first_party"}',
    ]

    for (const payload of payloads) {
      const { accounts } = clientFor({
        status: 200,
        headers: { 'X-Request-Id': 'req-13' },
        bodyBytes: envelope(payload),
      })
      expect(await detailOf(accounts.get('acct-1'))).toEqual({
        kind: 'contract_violation',
        correlationId: 'req-13',
      })
    }
  })

  /**
   * `status` arrives from a consumer-implemented transport, so its declared type
   * is not a runtime guarantee. Both range comparisons are false for NaN, which
   * without an integer check would read a broken response as a success.
   */
  it('treats a non-integer status as a failure rather than a success', async () => {
    for (const status of [Number.NaN, 200.5, Number.POSITIVE_INFINITY]) {
      const { accounts } = clientFor({
        status: status as number,
        bodyBytes: envelope(COMPLETE_ACCOUNT),
      })

      const detail = await detailOf(accounts.get('acct-1'))
      expect(detail.kind).toBe('api')
    }
  })

  /**
   * The correlation id is a server-supplied header and it reaches
   * `DaaError.message`, which a consuming app is likely to log verbatim. A
   * header carrying CR/LF could otherwise forge log lines.
   *
   * Only the control characters go. The surrounding text stays, because the
   * risk is a forged log *record*, not the words in one — and stripping more
   * would mangle a legitimate id. An ordinary correlation id is printable, so
   * this is a no-op on it, which the second case pins.
   */
  it('strips control characters from the correlation id in the message', async () => {
    const hostile = 'req-1\r\nWARN Injected log line'
    const { accounts } = clientFor({
      status: 500,
      headers: { 'X-Request-Id': hostile },
      bodyBytes: null,
    })

    try {
      await accounts.get('acct-1')
      throw new Error('expected the read to fail')
    } catch (err) {
      const message = (err as Error).message
      expect(message).not.toContain('\n')
      expect(message).not.toContain('\r')
      expect(message).toContain('req-1')
      expect(message).toContain('WARN Injected log line')
    }
  })

  /**
   * The other half: sanitising does not cost the value. A real correlation id
   * survives byte for byte, so the message is where a caller gets the exact
   * header — which is why the `api` detail does not need to carry a copy.
   */
  it('leaves an ordinary correlation id untouched in the message', async () => {
    const real = '8f3c1e2a-4b5d-4e6f-9a0b-1c2d3e4f5a6b'
    const { accounts } = clientFor({
      status: 500,
      headers: { 'X-Request-Id': real },
      bodyBytes: null,
    })

    try {
      await accounts.get('acct-1')
      throw new Error('expected the read to fail')
    } catch (err) {
      expect((err as Error).message).toContain(`(requestId=${real})`)
    }
  })

  /** No field name from the response reaches the error a consumer sees. */
  it('does not put a response field name in the error message', async () => {
    const { accounts } = clientFor({ status: 200, bodyBytes: envelope('{"accountId":"acct-1"}') })

    try {
      await accounts.get('acct-1')
      throw new Error('expected the read to fail')
    } catch (err) {
      expect(isDaaError(err)).toBe(true)
      expect((err as Error).message).not.toContain('entityId')
      expect((err as Error).message).not.toContain('balances')
    }
  })

  /** The receive address is the field a self-custody consumer opens the account for. */
  it('surfaces the deposit address and balances a self custody account carries', async () => {
    const { accounts } = okClient(
      '{"accountId":"acct-1","balances":[{"amount":"10.500000","currency":"USD"}],' +
        '"entityId":"e","purpose":"custody","status":"active","type":"first_party",' +
        '"custodyType":"self","blockchain":"ETH","depositAddress":"0xabc"}',
    )

    const account = await accounts.get('acct-1')

    expect(account.depositAddress).toBe('0xabc')
    expect(account.blockchain).toBe('ETH')
    expect(account.custodyType).toEqual({ kind: 'self' })
    expect((account.balances[0] as Money).amount).toBe('10.500000')
  })
})

describe('the failure path', () => {
  it('maps a status other than 200 onto the api error carrying the status', async () => {
    for (const status of [201, 204, 299, 400, 401, 404, 409, 500, 503]) {
      const { accounts } = clientFor({
        status,
        headers: { 'X-Request-Id': `req-${status}` },
        bodyBytes: bytes(`{"status":{"code":${status * 10},"message":"nope"}}`),
      })

      const detail = await detailOf(accounts.get('acct-1'))
      // Exactly the `api` variant and nothing more. The correlation id
      // is deliberately absent: the error model puts it on `contract_violation`
      // only, and it reaches the caller through the message.
      expect(detail).toEqual({
        kind: 'api',
        httpStatus: status,
        daaStatusCode: status * 10,
        retryable: status === 429 || status >= 500,
      })
    }
  })

  /**
   * A read is idempotent, so a `429` or `5xx` may be retried; a `4xx` will not
   * become a success on a second attempt. The DAA status code is carried but never
   * consulted — the error model's rule is that an unknown code stays observable and
   * is never guessed retryable.
   */
  it('marks only 429 and 5xx retryable', async () => {
    for (const [status, retryable] of [
      [400, false],
      [404, false],
      [428, false],
      [429, true],
      [499, false],
      [500, true],
      [599, true],
    ] as const) {
      const { accounts } = clientFor({ status })
      expect(await detailOf(accounts.get('acct-1'))).toMatchObject({ kind: 'api', retryable })
    }
  })

  /** The error detail is best effort: losing the whole error because it did not parse would be worse. */
  it('reports the api error even when the body carries no readable status code', async () => {
    for (const bodyBytes of [
      null,
      bytes(''),
      bytes('<html>gateway timeout</html>'),
      bytes('{}'),
      bytes('{"status":{}}'),
    ]) {
      const { accounts } = clientFor({ status: 502, bodyBytes })
      expect(await detailOf(accounts.get('acct-1'))).toEqual({
        kind: 'api',
        httpStatus: 502,
        retryable: true,
      })
    }
  })

  it('carries a non-numeric DAA status code as the string the service sent', async () => {
    const { accounts } = clientFor({
      status: 400,
      bodyBytes: bytes('{"status":{"code":"BAD_REQUEST"}}'),
    })
    expect(await detailOf(accounts.get('acct-1'))).toMatchObject({ daaStatusCode: 'BAD_REQUEST' })
  })

  /** The correlation id is server-generated, so it is the one response value worth printing. */
  it('finds the correlation id whichever casing the transport uses', async () => {
    for (const name of ['X-Request-Id', 'x-request-id', 'X-REQUEST-ID']) {
      const { accounts } = clientFor({ status: 404, headers: { [name]: 'req-9' } })
      try {
        await accounts.get('acct-1')
        throw new Error('expected the read to fail')
      } catch (err) {
        expect((err as Error).message).toContain('req-9')
      }
    }
  })

  it('reports an absent correlation id as absent rather than as an empty string', async () => {
    const { accounts } = clientFor({ status: 200, bodyBytes: bytes('{"data":null}') })
    expect(await detailOf(accounts.get('acct-1'))).toEqual({ kind: 'contract_violation' })
  })

  it('reports a consumer transport failure as a transport error with it as the cause', async () => {
    const failure = new Error('dns')
    const transport: DaaTransport = {
      async send() {
        throw failure
      },
    }

    await expect(
      createDaaUserClient(transport, 'production', NO_SIGNING).accounts.get('acct-1'),
    ).rejects.toMatchObject({
      detail: { kind: 'transport', retryable: true },
      cause: failure,
    })
  })
})

describe('reachability', () => {
  /**
   * The client is reachable only through `DaaClient.forUser`, which takes a
   * user context an `ACTIVE` Device Registration Complete produced.
   * `createDaaUserClient` is the internal factory behind it and is not on the
   * public entry, so a consumer cannot build the operations surface — or the
   * signing material it requires — for itself.
   */
  it('is reached only through the internal user-client factory', () => {
    const transport: DaaTransport = {
      async send() {
        return { status: 200, headers: {}, bodyBytes: null }
      },
    }
    const user = createDaaUserClient(transport, 'production', NO_SIGNING)
    expect(typeof user.accounts.get).toBe('function')
    expect(Object.isFrozen(user)).toBe(true)
    expect(Object.isFrozen(user.accounts)).toBe(true)
  })
})
