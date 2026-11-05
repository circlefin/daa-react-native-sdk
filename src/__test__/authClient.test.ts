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

import { requireOptionalNativeModule } from 'expo-modules-core'
import { AuthClient } from '../api/AuthClient'
import { requireDaaRegistrationNative } from '../auth/daaRegistrationNative'
import { registrationCodeChallengeS256 } from '../auth/registrationCodeVerifier'
import { DEVICE_KEY_POLICY } from '../config'
import { fromBase64Url } from '../crypto/base64url'
import { p256JwkThumbprint } from '../crypto/jwkThumbprint'
import { DaaClient } from '../DaaClient'
import { isDaaError } from '../errors'
import type { DaaSdkError } from '../errors'
import { PreparedSocialLogin } from '../models/PreparedSocialLogin'
import type { DaaHttpRequest, DaaHttpResponse, DaaTransport } from '../transport/DaaTransport'
import { isUuidV4 } from '../validation/uuid'
import {
  generateReceiptSigningKey,
  receiptClaims,
  signReceipt,
  trustAnchorFor,
  type ReceiptSigningKey,
} from './prepareReceiptSigning'

/**
 * `AuthClient.prepareSocialLogin`, end to end through the client.
 *
 * The load-bearing assertions are two contract requirements, and both are
 * pinned literally rather than by regex:
 *
 * - the path is `/v1/accounts/auth/loginRequests` with no `/social/` segment
 *   (camelCase; contract `prepareSocialLogin`);
 * - the body's key set is what the service accepts (no
 *   `registrationCodeChallengeMethod`).
 */

class RecordingTransport implements DaaTransport {
  readonly sent: DaaHttpRequest[] = []

  constructor(private readonly response: DaaHttpResponse) {}

  async send(request: DaaHttpRequest): Promise<DaaHttpResponse> {
    this.sent.push(request)
    return this.response
  }
}

const LOGIN_REQUEST_ID = '3f1a2b4c-5d6e-4f70-8192-a3b4c5d6e7f8'
const CLIENT_ENTITY_ID = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
const NONCE = 'n'.repeat(48)
const STATE = 's'.repeat(48)
const RECEIPT = `eyJhbGciOiJFUzI1NiJ9.${'p'.repeat(64)}.c2ln`
const EXPIRES_AT = '2026-08-26T12:00:00Z'

const PREPARED = `{"loginRequestId":"${LOGIN_REQUEST_ID}","oidcNonce":"${NONCE}","oidcState":"${STATE}","expiresAt":"${EXPIRES_AT}"}`

function envelope(payload: string): Uint8Array {
  return new TextEncoder().encode(`{"data":${payload}}`)
}

function clientFor(response: Partial<DaaHttpResponse>): {
  client: AuthClient
  transport: RecordingTransport
} {
  const transport = new RecordingTransport({
    status: response.status ?? 201,
    headers: response.headers ?? { 'X-Request-Id': 'req-1' },
    bodyBytes: response.bodyBytes ?? envelope(PREPARED),
  })
  return { client: new AuthClient({ transport }), transport }
}

function sentBody(transport: RecordingTransport): Record<string, unknown> {
  const request = transport.sent[0]
  if (request === undefined || request.bodyBytes === null) {
    throw new Error('expected a request with a body')
  }
  return JSON.parse(new TextDecoder().decode(request.bodyBytes)) as Record<string, unknown>
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
  it('posts to the contract path, with no /social/ segment', async () => {
    const { client, transport } = clientFor({})
    await client.prepareSocialLogin({ provider: 'GOOGLE' })

    expect(transport.sent).toHaveLength(1)
    expect(transport.sent[0]?.method).toBe('POST')
    expect(transport.sent[0]?.path).toBe('/v1/accounts/auth/loginRequests')
    expect(transport.sent[0]?.path).not.toMatch(/social/)
    expect(transport.sent[0]?.query).toBeNull()
    expect(transport.sent[0]?.headers).toEqual({ 'Content-Type': 'application/json' })
  })

  it('sends exactly the PrepareSocialLoginRequest fields', async () => {
    const { client, transport } = clientFor({})
    await client.prepareSocialLogin({ provider: 'APPLE' })

    expect(Object.keys(sentBody(transport)).sort()).toEqual([
      'idempotencyKey',
      'provider',
      'registrationCodeChallenge',
      'registrationFlowPublicKey',
    ])
  })

  it('sends no AuthKey material of any kind', async () => {
    const { client, transport } = clientFor({})
    await client.prepareSocialLogin({ provider: 'GOOGLE' })

    const body = sentBody(transport)
    for (const forbidden of [
      'authKeyPublicKey',
      'authKeyId',
      'authKeyThumbprint',
      'publicKey',
      'thumbprint',
      'jkt',
      'kid',
      'installationId',
      'profileId',
    ]) {
      expect(body[forbidden]).toBeUndefined()
    }
    const request = transport.sent[0]
    if (request === undefined || request.bodyBytes === null) {
      throw new Error('expected a request with a body')
    }
    // Belt and braces: nothing anywhere in the raw bytes names an AuthKey, and no
    // device-authorization header rides along.
    expect(new TextDecoder().decode(request.bodyBytes)).not.toMatch(/authKey/i)
    expect(Object.keys(request.headers)).not.toContain('X-Device-Authorization')
  })

  it('sends an S256 challenge and the flow public key in the pinned wire forms', async () => {
    const { client, transport } = clientFor({})
    await client.prepareSocialLogin({ provider: 'GOOGLE' })

    const body = sentBody(transport)
    expect(body.provider).toBe('GOOGLE')
    expect(body.registrationCodeChallenge).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(body.registrationFlowPublicKey).toMatch(/^[A-Za-z0-9_-]{122}$/)
    expect(fromBase64Url(body.registrationFlowPublicKey as string)).toHaveLength(91)
    expect(isUuidV4(body.idempotencyKey as string)).toBe(true)
  })

  it('does not send the verifier — only its digest goes out at Prepare', async () => {
    const { client, transport } = clientFor({})
    await client.prepareSocialLogin({ provider: 'GOOGLE' })

    const body = sentBody(transport)
    const challenge = body.registrationCodeChallenge as string
    // The verifier is unreachable by construction, so this asserts the negative
    // that is checkable: the challenge is a digest, so it cannot itself be the
    // preimage the server later matches it against.
    expect(registrationCodeChallengeS256(challenge)).not.toBe(challenge)
    expect(Object.keys(body)).not.toContain('registrationCodeVerifier')
    // No other value on the body hashes to the challenge either, so the verifier
    // did not ride along under a different field name.
    for (const value of Object.values(body)) {
      if (typeof value === 'string' && value !== challenge) {
        expect(registrationCodeChallengeS256(value)).not.toBe(challenge)
      }
    }
  })

  it('mints fresh attempt material per call', async () => {
    const transport = new RecordingTransport({
      status: 201,
      headers: {},
      bodyBytes: envelope(PREPARED),
    })
    const client = new AuthClient({ transport })

    await client.prepareSocialLogin({ provider: 'GOOGLE' })
    await client.prepareSocialLogin({ provider: 'GOOGLE' })

    const bodies = transport.sent.map((request) => {
      if (request.bodyBytes === null) {
        throw new Error('expected a request with a body')
      }
      return JSON.parse(new TextDecoder().decode(request.bodyBytes)) as Record<string, unknown>
    })
    expect(bodies[0]?.idempotencyKey).not.toBe(bodies[1]?.idempotencyKey)
    expect(bodies[0]?.registrationCodeChallenge).not.toBe(bodies[1]?.registrationCodeChallenge)
    expect(bodies[0]?.registrationFlowPublicKey).not.toBe(bodies[1]?.registrationFlowPublicKey)
  })

  it('serializes the body once and sends that same slice', async () => {
    const { client, transport } = clientFor({})
    await client.prepareSocialLogin({ provider: 'GOOGLE' })

    const request = transport.sent[0]
    if (request === undefined || request.bodyBytes === null) {
      throw new Error('expected a request with a body')
    }
    const text = new TextDecoder().decode(request.bodyBytes)
    // Key order is the contract's declaration order, and it is whatever
    // `serializeBody` emitted — nothing re-serializes or canonicalizes it.
    expect(text.indexOf('"idempotencyKey"')).toBeLessThan(text.indexOf('"provider"'))
    expect(text.indexOf('"provider"')).toBeLessThan(text.indexOf('"registrationCodeChallenge"'))
    expect(text.indexOf('"registrationCodeChallenge"')).toBeLessThan(
      text.indexOf('"registrationFlowPublicKey"'),
    )
  })

  it('rejects a provider that is not an uppercase registry key, before sending anything', async () => {
    for (const provider of ['google', 'Google', '', 'GOOGLE-X', 'G'.repeat(65), '1GOOGLE']) {
      const { client, transport } = clientFor({})
      expect(await detailOf(client.prepareSocialLogin({ provider }))).toEqual({
        kind: 'contract_violation',
      })
      expect(transport.sent).toHaveLength(0)
    }
  })

  it('rejects a non-object input', async () => {
    const { client } = clientFor({})
    for (const input of [null, undefined, 'GOOGLE', ['GOOGLE']]) {
      expect(
        await detailOf(client.prepareSocialLogin(input as unknown as { provider: string })),
      ).toEqual({ kind: 'contract_violation' })
    }
  })
})

describe('the response', () => {
  it('returns the PreparedSocialLogin fields and nothing about an AuthKey', async () => {
    const { client } = clientFor({})
    const prepared = await client.prepareSocialLogin({ provider: 'GOOGLE' })

    expect(prepared).toBeInstanceOf(PreparedSocialLogin)
    expect(Object.keys(prepared).sort()).toEqual([
      'expiresAt',
      'loginRequestId',
      'oidcNonce',
      'oidcState',
      'prepareReceiptJws',
    ])
    expect(prepared.loginRequestId).toBe(LOGIN_REQUEST_ID)
    expect(prepared.oidcNonce).toBe(NONCE)
    expect(prepared.oidcState).toBe(STATE)
    expect(prepared.prepareReceiptJws).toBeNull()
    expect(prepared.expiresAt).toBe(EXPIRES_AT)
    expect(Object.isFrozen(prepared)).toBe(true)
  })

  it('returns a usable PreparedSocialLogin from the body the service sends', async () => {
    // The `201` body below is a captured response to this client's own
    // Prepare request. It differs from the contract in two ways —
    // `expiresAt` is a JSON number of epoch milliseconds, and there is no
    // `prepareReceiptJws` — so this is the end-to-end case, not just the decoder's.
    const { client } = clientFor({
      bodyBytes: new TextEncoder().encode(
        '{"data":{"loginRequestId":"9f6ead8b-ff88-43fc-af00-7016eef7f4b3",' +
          '"oidcNonce":"V3dQJq2pX2-t70oIlt0EX7I6oZLo_id94-43ywbCAL8",' +
          '"oidcState":"VVOX5X68MHIBzK2K8eVOtad3pQAFGs2vDxY43QosYAA",' +
          '"expiresAt":1788290024580}}',
      ),
    })
    const prepared = await client.prepareSocialLogin({ provider: 'GOOGLE' })

    expect(prepared).toBeInstanceOf(PreparedSocialLogin)
    expect(prepared.loginRequestId).toBe('9f6ead8b-ff88-43fc-af00-7016eef7f4b3')
    expect(prepared.prepareReceiptJws).toBeNull()
    // Normalised at the decode boundary: the public field is the ISO-8601 string
    // whichever form arrived, so a consumer never branches on the wire's type.
    expect(prepared.expiresAt).toBe('2026-09-01T19:13:44.580Z')
  })

  it('ignores a receipt when no trust anchor is pinned, and login proceeds as if none arrived', async () => {
    // Anything in the receipt member — a well-formed JWS, a malformed string, a
    // value of the wrong type — is ignored alike, and none reaches the application.
    for (const receiptMember of [`"${RECEIPT}"`, '"not-a-jws"', '42', '{"alg":"none"}']) {
      const { client } = clientFor({
        bodyBytes: envelope(
          `{"loginRequestId":"${LOGIN_REQUEST_ID}","oidcNonce":"${NONCE}","oidcState":"${STATE}","expiresAt":"${EXPIRES_AT}","prepareReceiptJws":${receiptMember}}`,
        ),
      })
      const prepared = await client.prepareSocialLogin({ provider: 'GOOGLE' })
      expect(prepared).toBeInstanceOf(PreparedSocialLogin)
      expect(prepared.loginRequestId).toBe(LOGIN_REQUEST_ID)
      expect(prepared.oidcNonce).toBe(NONCE)
      expect(prepared.prepareReceiptJws).toBeNull()
    }
  })

  it('holds the attempt secret privately: the verifier is on no enumerable surface', async () => {
    const { client, transport } = clientFor({})
    const prepared = await client.prepareSocialLogin({ provider: 'GOOGLE' })
    const challenge = sentBody(transport).registrationCodeChallenge as string

    const serialized = JSON.stringify(prepared)
    expect(serialized).not.toMatch(/verifier/i)
    // Whatever the verifier is, its digest is the challenge. If the verifier had
    // leaked onto an enumerable field, hashing every string on the object would
    // reproduce the challenge.
    for (const value of Object.values(prepared as unknown as Record<string, unknown>)) {
      if (typeof value === 'string') {
        expect(registrationCodeChallengeS256(value)).not.toBe(challenge)
      }
    }
  })

  it('does not put the idToken into the error when Social Session fails', async () => {
    const { client } = clientFor({})
    const prepared = await client.prepareSocialLogin({ provider: 'GOOGLE' })

    // This transport only knows Prepare's 201; Session is a different call.
    const detail = await detailOf(
      prepared.completeSocialSession({
        idToken: 'ID_TOKEN_MARKER',
        clientEntityId: CLIENT_ENTITY_ID,
      }),
    )
    expect(detail.kind).toBe('api')
    await prepared
      .completeSocialSession({ idToken: 'ID_TOKEN_MARKER', clientEntityId: CLIENT_ENTITY_ID })
      .catch((err: unknown) => {
        expect((err as Error).message).not.toMatch(/ID_TOKEN_MARKER/)
      })
  })

  it('releases the flow key when completeSocialSession fails closed', async () => {
    let releaseCalls = 0
    const transport = new RecordingTransport({
      status: 201,
      headers: {},
      bodyBytes: envelope(PREPARED),
    })
    const client = new AuthClient({
      transport,
      registrationFlowKeys: {
        async generate() {
          return {
            async publicKeySpkiBase64Url() {
              return 'I'.repeat(122)
            },
            async signExactBytes() {
              throw new Error('flow-key sign unused in this test')
            },
            async release() {
              releaseCalls += 1
            },
          }
        },
      },
    })
    const prepared = await client.prepareSocialLogin({ provider: 'GOOGLE' })
    expect(releaseCalls).toBe(0)

    await expect(
      prepared.completeSocialSession({ idToken: 'token', clientEntityId: CLIENT_ENTITY_ID }),
    ).rejects.toBeDefined()
    expect(releaseCalls).toBe(1)
  })

  it('releases the flow key when the application abandons a successful Prepare', async () => {
    let releaseCalls = 0
    const transport = new RecordingTransport({
      status: 201,
      headers: {},
      bodyBytes: envelope(PREPARED),
    })
    const client = new AuthClient({
      transport,
      registrationFlowKeys: {
        async generate() {
          return {
            async publicKeySpkiBase64Url() {
              return 'I'.repeat(122)
            },
            async signExactBytes() {
              throw new Error('flow-key sign unused in this test')
            },
            async release() {
              releaseCalls += 1
            },
          }
        },
      },
    })
    const prepared = await client.prepareSocialLogin({ provider: 'GOOGLE' })
    expect(releaseCalls).toBe(0)

    await prepared.abandon()
    expect(releaseCalls).toBe(1)
    await prepared.abandon()
    expect(releaseCalls).toBe(2)
  })

  it('maps 410 to login_request_expired', async () => {
    const { client } = clientFor({ status: 410, bodyBytes: null })
    expect(await detailOf(client.prepareSocialLogin({ provider: 'GOOGLE' }))).toEqual({
      kind: 'login_request_expired',
    })
  })

  it('maps 409 with IDEMPOTENCY_KEY_REUSED to idempotency_conflict, carrying the key the SDK minted', async () => {
    const { client, transport } = clientFor({
      status: 409,
      bodyBytes: new TextEncoder().encode('{"code":420034,"message":"m","externalMessage":"e"}'),
    })
    const detail = await detailOf(client.prepareSocialLogin({ provider: 'GOOGLE' }))

    expect(detail.kind).toBe('idempotency_conflict')
    if (detail.kind === 'idempotency_conflict') {
      expect(detail.idempotencyKey).toBe(sentBody(transport).idempotencyKey)
    }
  })

  it('treats any other status, including another 2xx, as an api failure', async () => {
    for (const status of [200, 202, 401, 429, 503]) {
      const { client } = clientFor({ status, bodyBytes: envelope(PREPARED) })
      const detail = await detailOf(client.prepareSocialLogin({ provider: 'GOOGLE' }))
      expect(detail.kind).toBe('api')
      if (detail.kind === 'api') {
        expect(detail.httpStatus).toBe(status)
        expect(detail.retryable).toBe(status === 429 || status >= 500)
      }
    }
  })

  it('reports a response it cannot read as a contract violation with the correlation id', async () => {
    const { client } = clientFor({
      headers: { 'X-Request-Id': 'req-7' },
      bodyBytes: envelope('{"loginRequestId":"not-a-uuid"}'),
    })
    expect(await detailOf(client.prepareSocialLogin({ provider: 'GOOGLE' }))).toEqual({
      kind: 'contract_violation',
      correlationId: 'req-7',
    })
  })

  it('rethrows whatever the consumer transport threw, unchanged', async () => {
    const failure = new Error('offline')
    const client = new AuthClient({
      transport: {
        async send() {
          throw failure
        },
      },
    })
    await expect(client.prepareSocialLogin({ provider: 'GOOGLE' })).rejects.toBe(failure)
  })

  it('sends the injected provider key verbatim, not the native default', async () => {
    // Pins the `registrationFlowKeys` seam's contract. Production defaults to
    // native DaaRegistration; this is the only test that substitutes the
    // provider, so without it the swap's only contract would be untested.
    const injected = 'I'.repeat(122)
    let generateCalls = 0
    let releaseCalls = 0
    const transport = new RecordingTransport({
      status: 201,
      headers: {},
      bodyBytes: envelope(PREPARED),
    })
    const client = new AuthClient({
      transport,
      registrationFlowKeys: {
        async generate() {
          generateCalls += 1
          return {
            async publicKeySpkiBase64Url() {
              return injected
            },
            async signExactBytes() {
              throw new Error('flow-key sign unused in this test')
            },
            async release() {
              releaseCalls += 1
            },
          }
        },
      },
    })

    await client.prepareSocialLogin({ provider: 'GOOGLE' })

    expect(generateCalls).toBe(1)
    expect(releaseCalls).toBe(0)
    // Verbatim: the client must not re-encode or normalize what the provider
    // returned. A native provider hands back the platform's own SPKI encoding.
    expect(sentBody(transport).registrationFlowPublicKey).toBe(injected)
  })

  it('releases the flow key when Prepare fails after minting it', async () => {
    let releaseCalls = 0
    const client = new AuthClient({
      transport: {
        async send() {
          throw new Error('offline')
        },
      },
      registrationFlowKeys: {
        async generate() {
          return {
            async publicKeySpkiBase64Url() {
              return 'I'.repeat(122)
            },
            async signExactBytes() {
              throw new Error('flow-key sign unused in this test')
            },
            async release() {
              releaseCalls += 1
            },
          }
        },
      },
    })

    await expect(client.prepareSocialLogin({ provider: 'GOOGLE' })).rejects.toThrow('offline')
    expect(releaseCalls).toBe(1)
  })

  it('does not let a throwing release replace the transport error', async () => {
    const failure = new Error('offline')
    const client = new AuthClient({
      transport: {
        async send() {
          throw failure
        },
      },
      registrationFlowKeys: {
        async generate() {
          return {
            async publicKeySpkiBase64Url() {
              return 'I'.repeat(122)
            },
            async signExactBytes() {
              throw new Error('flow-key sign unused in this test')
            },
            async release() {
              throw new Error('release blew up')
            },
          }
        },
      },
    })

    await expect(client.prepareSocialLogin({ provider: 'GOOGLE' })).rejects.toBe(failure)
  })
})

/**
 * A transport standing in for DAA with a receipt signer configured: it reads
 * the challenge and flow key the SDK sent and signs a receipt over them, the
 * way the service's Prepare does. `tamper` models a relay rewriting the
 * response on the way back.
 */
class ReceiptIssuingTransport implements DaaTransport {
  readonly sent: DaaHttpRequest[] = []

  constructor(
    private readonly key: ReceiptSigningKey,
    private readonly tamper: (
      claims: Record<string, unknown>,
      data: Record<string, unknown>,
    ) => void = () => {},
  ) {}

  async send(request: DaaHttpRequest): Promise<DaaHttpResponse> {
    this.sent.push(request)
    const body = JSON.parse(new TextDecoder().decode(request.bodyBytes!)) as Record<string, string>
    const now = Math.floor(Date.now() / 1000)
    const claims = receiptClaims(
      {
        loginRequestId: LOGIN_REQUEST_ID,
        nonce: NONCE,
        provider: body['provider']!,
        environment: 'sandbox',
        registrationCodeChallenge: body['registrationCodeChallenge']!,
        registrationFlowKeyThumbprint: p256JwkThumbprint(
          fromBase64Url(body['registrationFlowPublicKey']!),
        ),
      },
      now,
    )
    const data: Record<string, unknown> = {
      loginRequestId: LOGIN_REQUEST_ID,
      oidcNonce: NONCE,
      oidcState: STATE,
      expiresAt: EXPIRES_AT,
    }
    this.tamper(claims, data)
    if (!('prepareReceiptJws' in data)) {
      data['prepareReceiptJws'] = await signReceipt(this.key, claims)
    }
    return {
      status: 201,
      headers: {},
      bodyBytes: new TextEncoder().encode(JSON.stringify({ data })),
    }
  }
}

describe('the Prepare receipt with a trust anchor pinned', () => {
  let key: ReceiptSigningKey

  beforeAll(async () => {
    key = await generateReceiptSigningKey('sandbox-receipt-1')
  })

  function anchoredClient(transport: DaaTransport): AuthClient {
    return new AuthClient({
      transport,
      environment: 'sandbox',
      prepareReceiptTrustAnchor: trustAnchorFor([key]),
    })
  }

  it('returns the PreparedSocialLogin when the receipt binds this attempt', async () => {
    const transport = new ReceiptIssuingTransport(key)
    const prepared = await anchoredClient(transport).prepareSocialLogin({ provider: 'GOOGLE' })
    expect(prepared.loginRequestId).toBe(LOGIN_REQUEST_ID)
    expect(prepared.oidcNonce).toBe(NONCE)
    expect(prepared.prepareReceiptJws).not.toBeNull()
  })

  it.each([
    [
      'a missing receipt',
      (_c: Record<string, unknown>, d: Record<string, unknown>) => {
        d['prepareReceiptJws'] = null
      },
    ],
    [
      'a malformed receipt',
      (_c: Record<string, unknown>, d: Record<string, unknown>) => {
        d['prepareReceiptJws'] = 'not-a-jws'
      },
    ],
    [
      'a receipt that is not a string',
      (_c: Record<string, unknown>, d: Record<string, unknown>) => {
        d['prepareReceiptJws'] = 42
      },
    ],
    [
      'a relay-substituted challenge',
      (c: Record<string, unknown>) => {
        c['registrationCodeChallenge'] = registrationCodeChallengeS256(
          'another-attempt-verifier-'.repeat(2),
        )
      },
    ],
    [
      'a relay-substituted flow key',
      (c: Record<string, unknown>) => {
        c['registrationFlowKeyThumbprint'] = 'xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M'
      },
    ],
    [
      "another attempt's nonce in the response",
      (_c: Record<string, unknown>, d: Record<string, unknown>) => {
        d['oidcNonce'] = 'z'.repeat(48)
      },
    ],
    [
      "another attempt's loginRequestId in the response",
      (_c: Record<string, unknown>, d: Record<string, unknown>) => {
        d['loginRequestId'] = CLIENT_ENTITY_ID
      },
    ],
    [
      'another environment',
      (c: Record<string, unknown>) => {
        c['environment'] = 'production'
      },
    ],
    [
      'an expired receipt',
      (c: Record<string, unknown>) => {
        c['iat'] = 1_700_000_000
        c['exp'] = 1_700_000_600
      },
    ],
  ])('fails closed on %s, before anything reaches the application', async (_name, tamper) => {
    const release = jest.spyOn(requireDaaRegistrationNative(), 'releaseRegistrationFlowKey')
    try {
      const transport = new ReceiptIssuingTransport(key, tamper)
      expect(
        await detailOf(anchoredClient(transport).prepareSocialLogin({ provider: 'GOOGLE' })),
      ).toEqual({ kind: 'prepare_receipt_invalid' })
      expect(release).toHaveBeenCalledTimes(1)
    } finally {
      release.mockRestore()
    }
  })

  it('fails closed on a receipt signed by a key the anchor does not pin', async () => {
    const stranger = await generateReceiptSigningKey(key.kid)
    const transport = new ReceiptIssuingTransport(stranger)
    expect(
      await detailOf(anchoredClient(transport).prepareSocialLogin({ provider: 'GOOGLE' })),
    ).toEqual({ kind: 'prepare_receipt_invalid' })
  })

  it('checks the requested provider, not one the relay reports', async () => {
    const transport = new ReceiptIssuingTransport(key, (c) => {
      c['provider'] = 'APPLE'
    })
    expect(
      await detailOf(anchoredClient(transport).prepareSocialLogin({ provider: 'GOOGLE' })),
    ).toEqual({ kind: 'prepare_receipt_invalid' })
  })
})

describe('DaaClient wiring', () => {
  it('exposes one frozen AuthClient over the configured transport', async () => {
    const transport = new RecordingTransport({
      status: 201,
      headers: {},
      bodyBytes: envelope(PREPARED),
    })
    const client = new DaaClient({
      appId: 'app-123',
      environment: 'sandbox',
      transport,
      keyPolicy: DEVICE_KEY_POLICY,
    })

    expect(client.auth).toBe(client.auth)
    expect(Object.isFrozen(client.auth)).toBe(true)
    await client.auth.prepareSocialLogin({ provider: 'GOOGLE' })
    expect(transport.sent[0]?.path).toBe('/v1/accounts/auth/loginRequests')
  })

  it('needs no secure-key store to prepare: forUser still fails closed', () => {
    const transport = new RecordingTransport({ status: 201, headers: {}, bodyBytes: null })
    const client = new DaaClient({
      appId: 'app-123',
      environment: 'sandbox',
      transport,
      keyPolicy: DEVICE_KEY_POLICY,
    })

    expect(() => client.auth).not.toThrow()
    expect(() => client.forUser({} as never)).toThrow(/ACTIVE DaaUserContext/)
  })

  it('exposes no resolveAuthKey on the public client.auth surface', () => {
    // TypeScript's `private` is erased at build time, so this must be a
    // runtime assertion, not a type-only one: it has to fail even against the
    // compiled JS a consumer actually runs. `client.auth` is the public entry
    // point (`DaaClient.auth`), and `resolveAuthKey` must not be a callable
    // member reachable from it — that would hand any JavaScript in the host
    // process a live handle to the enclave-held Owner AuthKey.
    const transport = new RecordingTransport({ status: 201, headers: {}, bodyBytes: null })
    const client = new DaaClient({
      appId: 'app-123',
      environment: 'sandbox',
      transport,
      keyPolicy: DEVICE_KEY_POLICY,
    })

    expect((client.auth as unknown as Record<string, unknown>).resolveAuthKey).toBeUndefined()
    expect(Object.getOwnPropertyNames(Object.getPrototypeOf(client.auth) as object)).not.toContain(
      'resolveAuthKey',
    )
  })

  it('constructs when DaaRegistration is absent; prepare fails closed', async () => {
    const requireNative = jest.mocked(requireOptionalNativeModule)
    const previous = requireNative.getMockImplementation()
    requireNative.mockImplementation(() => null)
    try {
      const transport = new RecordingTransport({
        status: 201,
        headers: {},
        bodyBytes: envelope(PREPARED),
      })
      const client = new DaaClient({
        appId: 'app-123',
        environment: 'sandbox',
        transport,
        keyPolicy: DEVICE_KEY_POLICY,
      })
      expect(client.auth).toBeDefined()
      await expect(client.auth.prepareSocialLogin({ provider: 'GOOGLE' })).rejects.toThrow(
        /native DaaRegistration module is not available/,
      )
    } finally {
      requireNative.mockReset()
      if (previous !== undefined) {
        requireNative.mockImplementation(previous)
      }
    }
  })
})
