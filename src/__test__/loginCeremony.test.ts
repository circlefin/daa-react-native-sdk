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
import { webCryptoRegistrationFlowKeyProvider } from '../auth/RegistrationFlowKey'
import { DEVICE_AUTHORIZATION_HEADER } from '../auth/deviceAuthorization'
import {
  DEVICE_REGISTRATION_COMPLETE_PATH,
  REGISTRATION_DEVICE_AUTHORIZATION_HEADER,
  REGISTRATION_FLOW_AUTHORIZATION_HEADER,
} from '../auth/registrationAuthorization'
import { registrationCodeChallengeS256 } from '../auth/registrationCodeVerifier'
import { fromBase64Url, toBase64Url } from '../crypto/base64url'
import { toArrayBuffer } from '../crypto/bytes'
import { p256JwkThumbprint, p256PublicJwkFromSpki } from '../crypto/jwkThumbprint'
import { sha256 } from '../crypto/sha256'
import { DEVICE_KEY_POLICY } from '../config'
import { DaaClient } from '../DaaClient'
import { isDaaError } from '../errors'
import { SOCIAL_SESSION_PATH } from '../models/PreparedSocialLogin'
import { InMemorySecureKeyStore } from '../securekey/InMemorySecureKey'
import type { DaaHttpRequest, DaaHttpResponse, DaaTransport } from '../transport/DaaTransport'
import { isUuidV4 } from '../validation/uuid'

/**
 * Social Session, AuthKey selection, Device Registration Complete, and
 * `DaaClient.forUser` — the rest of the login ceremony after Prepare.
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
const OWNER_BINDING_ID = '11111111-2222-4333-8444-555555555555'
const AUTH_KEY_ID = '99999999-8888-4777-8666-555555555555'
const NONCE = 'n'.repeat(48)
const STATE = 's'.repeat(48)
const EXPIRES_AT = '2026-08-26T12:00:00Z'
const HANDLE = 'h'.repeat(32)
const ID_TOKEN = 'ID_TOKEN_MARKER'

const PREPARED = `{"loginRequestId":"${LOGIN_REQUEST_ID}","oidcNonce":"${NONCE}","oidcState":"${STATE}","expiresAt":"${EXPIRES_AT}"}`
const SESSION = `{"registrationHandle":"${HANDLE}","clientEntityId":"${CLIENT_ENTITY_ID}","expiresAt":"${EXPIRES_AT}"}`
const ACTIVE = `{"deviceCredentialStatus":"active","ownerBindingId":"${OWNER_BINDING_ID}","authKeyId":"${AUTH_KEY_ID}","resolvedAt":"${EXPIRES_AT}"}`
const RECOVERY = `{"status":"RECOVERY_PENDING","recoveryReference":"${'r'.repeat(16)}","expiresAt":"${EXPIRES_AT}"}`
// No `status` member (the flat shape), but a `recoveryReference`
// alongside it — a payload that cannot honestly be resolved toward ACTIVE.
const ACTIVE_WITH_RECOVERY_FIELD = `{"deviceCredentialStatus":"active","ownerBindingId":"${OWNER_BINDING_ID}","authKeyId":"${AUTH_KEY_ID}","resolvedAt":"${EXPIRES_AT}","recoveryReference":"${'r'.repeat(16)}"}`
// Same ambiguity, the other `RECOVERY_PENDING` field: no `status`, but an
// `expiresAt` alongside the flat shape.
const ACTIVE_WITH_EXPIRES_AT_FIELD = `{"deviceCredentialStatus":"active","ownerBindingId":"${OWNER_BINDING_ID}","authKeyId":"${AUTH_KEY_ID}","resolvedAt":"${EXPIRES_AT}","expiresAt":"${EXPIRES_AT}"}`

function envelope(payload: string): Uint8Array {
  return new TextEncoder().encode(`{"data":${payload}}`)
}

function jsonResponse(status: number, payload: string): DaaHttpResponse {
  return { status, headers: { 'X-Request-Id': 'req-1' }, bodyBytes: envelope(payload) }
}

function compactJwt(payload: object, header: object = { alg: 'ES256' }): string {
  const encodedHeader = toBase64Url(new TextEncoder().encode(JSON.stringify(header)))
  const body = toBase64Url(new TextEncoder().encode(JSON.stringify(payload)))
  return `${encodedHeader}.${body}.c2ln`
}

function decodeJwsPayload(jws: string): Record<string, unknown> {
  const payload = jws.split('.')[1]
  if (payload === undefined) {
    throw new Error('expected a compact JWS')
  }
  return JSON.parse(new TextDecoder().decode(fromBase64Url(payload))) as Record<string, unknown>
}

function decodeJwsHeader(jws: string): Record<string, unknown> {
  const header = jws.split('.')[0]
  if (header === undefined) {
    throw new Error('expected a compact JWS')
  }
  return JSON.parse(new TextDecoder().decode(fromBase64Url(header))) as Record<string, unknown>
}

function sentJson(request: DaaHttpRequest): Record<string, unknown> {
  if (request.bodyBytes === null) {
    throw new Error('expected a request with a body')
  }
  return JSON.parse(new TextDecoder().decode(request.bodyBytes)) as Record<string, unknown>
}

function ceremonyClient(responses: DaaHttpResponse[]): {
  client: AuthClient
  transport: ScriptedTransport
  store: InMemorySecureKeyStore
} {
  const transport = new ScriptedTransport(responses)
  const store = new InMemorySecureKeyStore()
  const client = new AuthClient({
    transport,
    registrationFlowKeys: webCryptoRegistrationFlowKeyProvider(),
    secureKeys: store,
    identity: { appId: 'app-123', environment: 'sandbox' },
  })
  return { client, transport, store }
}

describe('Social Session', () => {
  it('posts loginRequestId, idToken, and clientEntityId to the contract path, then selects an AuthKey', async () => {
    const { client, transport, store } = ceremonyClient([
      jsonResponse(201, PREPARED),
      jsonResponse(200, SESSION),
    ])
    const prepared = await client.prepareSocialLogin({ provider: 'GOOGLE' })
    const pending = await prepared.completeSocialSession({
      idToken: ID_TOKEN,
      clientEntityId: CLIENT_ENTITY_ID,
    })

    expect(transport.sent).toHaveLength(2)
    const session = transport.sent[1]
    if (session === undefined || session.bodyBytes === null) {
      throw new Error('expected a Session request')
    }
    expect(session.method).toBe('POST')
    expect(session.path).toBe(SOCIAL_SESSION_PATH)
    expect(session.query).toBeNull()
    expect(session.headers).toEqual({ 'Content-Type': 'application/json' })
    expect(Object.keys(session.headers)).not.toContain('X-Device-Authorization')

    const body = sentJson(session)
    expect(Object.keys(body).sort()).toEqual([
      'clientEntityId',
      'idToken',
      'idempotencyKey',
      'loginRequestId',
    ])
    expect(body.loginRequestId).toBe(LOGIN_REQUEST_ID)
    expect(body.idToken).toBe(ID_TOKEN)
    expect(body.clientEntityId).toBe(CLIENT_ENTITY_ID)
    expect(new TextDecoder().decode(session.bodyBytes)).toBe(
      JSON.stringify({
        idempotencyKey: body.idempotencyKey,
        loginRequestId: LOGIN_REQUEST_ID,
        idToken: ID_TOKEN,
        clientEntityId: CLIENT_ENTITY_ID,
      }),
    )

    expect(pending.registrationHandle).toBe(HANDLE)
    expect(pending.clientEntityId).toBe(CLIENT_ENTITY_ID)
    expect(pending.expiresAt).toBe(EXPIRES_AT)
    const authKey = await store.resolveOrCreate({
      appId: 'app-123',
      environment: 'sandbox',
      clientEntityId: CLIENT_ENTITY_ID,
    })
    expect(authKey.resolution()).toBe('created')
  })

  // The service declares `clientEntityId` required with no resolve-or-create
  // fallback, so a bad one is a 400 rather than a login. Reject it locally,
  // before the attempt is spent, rather than spending it on a doomed request.
  it.each<[string, unknown]>([
    ['missing', undefined],
    ['null', null],
    ['not a UUID', 'not-a-uuid'],
    ['a UUID with surrounding text', ` ${CLIENT_ENTITY_ID} `],
    ['not a string', 42],
  ])('rejects a clientEntityId that is %s', async (_label, clientEntityId) => {
    const { client, transport } = ceremonyClient([jsonResponse(201, PREPARED)])
    const prepared = await client.prepareSocialLogin({ provider: 'GOOGLE' })

    const error: unknown = await prepared
      .completeSocialSession({ idToken: ID_TOKEN, clientEntityId } as {
        idToken: string
        clientEntityId: string
      })
      .catch((err: unknown) => err)

    expect(isDaaError(error)).toBe(true)
    if (isDaaError(error)) {
      expect(error.detail.kind).toBe('contract_violation')
    }
    // Prepare and nothing else: the Session request was never sent.
    expect(transport.sent).toHaveLength(1)
  })

  it('fails closed when an Owner grant is missing registrationFlowKeyThumbprint', async () => {
    const grant = compactJwt({ sub: 'GRANT_MARKER', aud: 'circle-digital-asset-accounts' })
    const { client } = ceremonyClient([
      jsonResponse(201, PREPARED),
      jsonResponse(
        200,
        `{"registrationHandle":"${HANDLE}","clientEntityId":"${CLIENT_ENTITY_ID}","expiresAt":"${EXPIRES_AT}","ownerGrant":"${grant}"}`,
      ),
    ])
    const prepared = await client.prepareSocialLogin({ provider: 'GOOGLE' })
    try {
      await prepared.completeSocialSession({ idToken: ID_TOKEN, clientEntityId: CLIENT_ENTITY_ID })
    } catch (err) {
      expect(isDaaError(err)).toBe(true)
      if (isDaaError(err)) {
        expect(err.detail.kind).toBe('contract_violation')
      }
      expect((err as Error).message).not.toMatch(/GRANT_MARKER/)
      expect((err as Error).message).not.toMatch(/ID_TOKEN_MARKER/)
      expect(JSON.stringify(err)).not.toMatch(/GRANT_MARKER/)
      return
    }
    throw new Error('expected missing grant thumbprint to fail closed')
  })

  it('accepts an Owner grant only when registrationFlowKeyThumbprint matches the flow key', async () => {
    const transport: DaaTransport & { sent: DaaHttpRequest[] } = {
      sent: [],
      async send(request) {
        transport.sent.push(request)
        if (transport.sent.length === 1) {
          return jsonResponse(201, PREPARED)
        }
        const prepare = transport.sent[0]
        if (prepare === undefined) {
          throw new Error('expected Prepare to be sent first')
        }
        const flowSpki = fromBase64Url(sentJson(prepare).registrationFlowPublicKey as string)
        const grant = compactJwt({
          registrationFlowKeyThumbprint: p256JwkThumbprint(flowSpki),
        })
        return jsonResponse(
          200,
          `{"registrationHandle":"${HANDLE}","clientEntityId":"${CLIENT_ENTITY_ID}","expiresAt":"${EXPIRES_AT}","ownerGrant":"${grant}"}`,
        )
      },
    }
    const client = new AuthClient({
      transport,
      registrationFlowKeys: webCryptoRegistrationFlowKeyProvider(),
      secureKeys: new InMemorySecureKeyStore(),
      identity: { appId: 'app-123', environment: 'sandbox' },
    })
    const prepared = await client.prepareSocialLogin({ provider: 'GOOGLE' })
    const pending = await prepared.completeSocialSession({
      idToken: ID_TOKEN,
      clientEntityId: CLIENT_ENTITY_ID,
    })
    expect(pending.registrationHandle).toBe(HANDLE)
  })
})

describe('production AuthKey store reuse', () => {
  const requireNative = jest.mocked(requireOptionalNativeModule)

  it('reuses one NativeSecureKeyStore so concurrent Session completions share resolveOrCreate', async () => {
    let resolveCalls = 0
    const previous = requireNative.getMockImplementation()
    requireNative.mockImplementation((name: string) => {
      if (name === 'DaaSecureKey') {
        return {
          declaredKeyPolicy: () => DEVICE_KEY_POLICY,
          resolveOrCreate: async () => {
            resolveCalls += 1
            return 'created'
          },
          publicKeySpkiBase64Url: async () => 'I'.repeat(122),
          acknowledgeRegistration: async () => undefined,
        }
      }
      return previous?.(name) ?? null
    })

    try {
      const transport = new ScriptedTransport([
        jsonResponse(201, PREPARED),
        jsonResponse(201, PREPARED),
        jsonResponse(200, SESSION),
        jsonResponse(200, SESSION),
      ])
      const client = new AuthClient({
        transport,
        registrationFlowKeys: webCryptoRegistrationFlowKeyProvider(),
        identity: { appId: 'app-123', environment: 'sandbox' },
      })
      const first = await client.prepareSocialLogin({ provider: 'GOOGLE' })
      const second = await client.prepareSocialLogin({ provider: 'GOOGLE' })
      await Promise.all([
        first.completeSocialSession({ idToken: ID_TOKEN, clientEntityId: CLIENT_ENTITY_ID }),
        second.completeSocialSession({ idToken: ID_TOKEN, clientEntityId: CLIENT_ENTITY_ID }),
      ])

      expect(resolveCalls).toBe(1)
    } finally {
      requireNative.mockImplementation(previous ?? (() => null))
    }
  })
})

describe('Device Registration Complete', () => {
  it('signs and sends both registration proofs under their two headers: the flow proof with all 14 claims, the device proof with only the 10 request claims', async () => {
    const { client, transport, store } = ceremonyClient([
      jsonResponse(201, PREPARED),
      jsonResponse(200, SESSION),
      jsonResponse(200, ACTIVE),
    ])
    const prepared = await client.prepareSocialLogin({ provider: 'GOOGLE' })
    const pending = await prepared.completeSocialSession({
      idToken: ID_TOKEN,
      clientEntityId: CLIENT_ENTITY_ID,
    })
    const result = await pending.complete()

    expect(result.status).toBe('ACTIVE')
    if (result.status !== 'ACTIVE') {
      throw new Error('expected ACTIVE')
    }
    expect(result.context.clientEntityId).toBe(CLIENT_ENTITY_ID)
    expect(result.context.deviceContext.authKeyId).toBe(AUTH_KEY_ID)
    expect(result.context.deviceContext.deviceCredentialStatus).toBe('active')

    const complete = transport.sent[2]
    if (complete === undefined || complete.bodyBytes === null) {
      throw new Error('expected a Complete request')
    }
    expect(complete.method).toBe('POST')
    expect(DEVICE_REGISTRATION_COMPLETE_PATH).toBe('/v1/accounts/auth/deviceKeyRegistration')
    expect(complete.path).toBe('/v1/accounts/auth/deviceKeyRegistration')
    expect(complete.query).toBeNull()
    expect(Object.keys(complete.headers).sort()).toEqual(
      [
        'Content-Type',
        REGISTRATION_DEVICE_AUTHORIZATION_HEADER,
        REGISTRATION_FLOW_AUTHORIZATION_HEADER,
      ].sort(),
    )
    expect(complete.headers['Content-Type']).toBe('application/json')
    expect(REGISTRATION_DEVICE_AUTHORIZATION_HEADER).toBe('X-Device-Authorization')
    expect(REGISTRATION_FLOW_AUTHORIZATION_HEADER).toBe('X-Registration-Flow-Authorization')

    const body = sentJson(complete)
    expect(Object.keys(body).sort()).toEqual([
      'authKeyPublicKey',
      'idempotencyKey',
      'registrationCodeVerifier',
      'registrationHandle',
    ])
    expect(body.registrationHandle).toBe(HANDLE)
    // profile_id (the bound clientEntityId) travels only in the two JWS claim
    // sets, never in the HTTP body itself.
    expect(body).not.toHaveProperty('profileId')
    expect(body).not.toHaveProperty('existingDeviceApprovalJws')
    expect(new TextDecoder().decode(complete.bodyBytes)).toBe(JSON.stringify(body))

    // The verifier redeemed here must be the one minted before Prepare, not a
    // fresh one — that round-trip is the whole point of the challenge/verifier
    // exchange.
    const prepare = transport.sent[0]
    if (prepare === undefined || prepare.bodyBytes === null) {
      throw new Error('expected a Prepare request')
    }
    const prepareChallenge = sentJson(prepare).registrationCodeChallenge as string
    const prepareFlowPublicKey = sentJson(prepare).registrationFlowPublicKey as string
    expect(registrationCodeChallengeS256(body.registrationCodeVerifier as string)).toBe(
      prepareChallenge,
    )

    const deviceJws = complete.headers[REGISTRATION_DEVICE_AUTHORIZATION_HEADER]
    const flowJws = complete.headers[REGISTRATION_FLOW_AUTHORIZATION_HEADER]
    if (deviceJws === undefined || flowJws === undefined) {
      throw new Error('expected both X-Device-Authorization and X-Registration-Flow-Authorization')
    }

    // Both headers embed the signer's own P-256 public JWK, bound to the key
    // that actually holds each role: the proposed AuthKey for the device proof,
    // and the ephemeral flow key minted (and sent to Prepare) for the flow proof.
    const deviceHeader = decodeJwsHeader(deviceJws)
    expect(deviceHeader.alg).toBe('ES256')
    expect(deviceHeader.typ).toBe('daa-device-authorization+jws')
    expect(deviceHeader.kid).toBeUndefined()
    expect(deviceHeader.jwk).toEqual(
      p256PublicJwkFromSpki(fromBase64Url(body.authKeyPublicKey as string)),
    )

    const flowHeader = decodeJwsHeader(flowJws)
    expect(flowHeader.alg).toBe('ES256')
    expect(flowHeader.typ).toBe('daa-registration-flow-authorization+jws')
    expect(flowHeader.kid).toBeUndefined()
    expect(flowHeader.jwk).toEqual(p256PublicJwkFromSpki(fromBase64Url(prepareFlowPublicKey)))

    // Every claim DAA checks on Complete, with the right names and values. The flow proof carries all 14.
    const digest = toBase64Url(sha256(complete.bodyBytes))
    const devicePayload = decodeJwsPayload(deviceJws)
    const flowPayload = decodeJwsPayload(flowJws)
    expect(flowPayload.discriminator).toBe('device_key_registration.v1')
    expect(flowPayload.schema_version).toBe(1)
    expect(flowPayload.body_sha256).toBe(digest)
    expect(flowPayload.idempotency_key).toBe(body.idempotencyKey)
    expect(flowPayload.canonical_path).toBe('/v1/accounts/auth/deviceKeyRegistration')
    expect(flowPayload.method).toBe('POST')
    expect(flowPayload.aud).toBe('circle-digital-asset-accounts')
    expect(flowPayload.registration_handle_sha256).toBe(
      toBase64Url(sha256(new TextEncoder().encode(HANDLE))),
    )
    expect(flowPayload.profile_id).toBe(CLIENT_ENTITY_ID)
    expect(flowPayload.auth_key_thumbprint).toBe(
      p256JwkThumbprint(fromBase64Url(body.authKeyPublicKey as string)),
    )
    expect(flowPayload.code_verifier_sha256).toBe(
      registrationCodeChallengeS256(body.registrationCodeVerifier as string),
    )
    expect(flowPayload.code_verifier_sha256).toBe(prepareChallenge)
    expect(isUuidV4(flowPayload.jti as string)).toBe(true)
    expect(typeof flowPayload.iat).toBe('number')
    expect(flowPayload.exp).toBe((flowPayload.iat as number) + 300)
    expect(Object.keys(flowPayload).sort()).toEqual([
      'aud',
      'auth_key_thumbprint',
      'body_sha256',
      'canonical_path',
      'code_verifier_sha256',
      'discriminator',
      'exp',
      'iat',
      'idempotency_key',
      'jti',
      'method',
      'profile_id',
      'registration_handle_sha256',
      'schema_version',
    ])

    // The device proof carries only the 10 request claims — DAA
    // decodes it strictly and rejects any binding claim — with the same
    // values as the flow proof, bar jti.
    const flowJti = flowPayload.jti
    const flowRequestClaims = Object.fromEntries(
      Object.entries(flowPayload).filter(([name]) => name in devicePayload && name !== 'jti'),
    )
    const { jti: deviceJti, ...deviceRequestClaims } = devicePayload
    expect(deviceRequestClaims).toEqual(flowRequestClaims)
    expect(Object.keys(devicePayload).sort()).toEqual([
      'aud',
      'body_sha256',
      'canonical_path',
      'discriminator',
      'exp',
      'iat',
      'idempotency_key',
      'jti',
      'method',
      'schema_version',
    ])
    expect(isUuidV4(deviceJti as string)).toBe(true)
    expect(isUuidV4(flowJti as string)).toBe(true)
    expect(flowJti).not.toBe(deviceJti)

    const authKey = await store.resolveOrCreate({
      appId: 'app-123',
      environment: 'sandbox',
      clientEntityId: CLIENT_ENTITY_ID,
    })
    expect(authKey.resolution()).toBe('existing')
  })

  it('does not put JWS, verifier, or idToken into Complete errors', async () => {
    const { client, transport } = ceremonyClient([
      jsonResponse(201, PREPARED),
      jsonResponse(200, SESSION),
      { status: 400, headers: { 'X-Request-Id': 'req-1' }, bodyBytes: null },
    ])
    const prepared = await client.prepareSocialLogin({ provider: 'GOOGLE' })
    const pending = await prepared.completeSocialSession({
      idToken: ID_TOKEN,
      clientEntityId: CLIENT_ENTITY_ID,
    })
    try {
      await pending.complete()
    } catch (err) {
      const complete = transport.sent[2]
      const deviceJws = complete?.headers[REGISTRATION_DEVICE_AUTHORIZATION_HEADER]
      const flowJws = complete?.headers[REGISTRATION_FLOW_AUTHORIZATION_HEADER]
      const message = (err as Error).message
      expect(message).not.toMatch(/ID_TOKEN_MARKER/)
      if (deviceJws !== undefined) {
        expect(message).not.toContain(deviceJws)
      }
      if (flowJws !== undefined) {
        expect(message).not.toContain(flowJws)
      }
      expect(JSON.stringify(err)).not.toMatch(/ID_TOKEN_MARKER/)
      return
    }
    throw new Error('expected Complete to fail')
  })

  it('returns RECOVERY_PENDING without acknowledging the AuthKey', async () => {
    const { client, store } = ceremonyClient([
      jsonResponse(201, PREPARED),
      jsonResponse(200, SESSION),
      jsonResponse(200, RECOVERY),
    ])
    const prepared = await client.prepareSocialLogin({ provider: 'GOOGLE' })
    const pending = await prepared.completeSocialSession({
      idToken: ID_TOKEN,
      clientEntityId: CLIENT_ENTITY_ID,
    })
    const result = await pending.complete()
    expect(result.status).toBe('RECOVERY_PENDING')
    const authKey = await store.resolveOrCreate({
      appId: 'app-123',
      environment: 'sandbox',
      clientEntityId: CLIENT_ENTITY_ID,
    })
    expect(authKey.resolution()).toBe('created')
  })

  it('fails closed rather than acknowledging the AuthKey when status is absent but a recoveryReference is present', async () => {
    const { client, store } = ceremonyClient([
      jsonResponse(201, PREPARED),
      jsonResponse(200, SESSION),
      jsonResponse(200, ACTIVE_WITH_RECOVERY_FIELD),
    ])
    const prepared = await client.prepareSocialLogin({ provider: 'GOOGLE' })
    const pending = await prepared.completeSocialSession({
      idToken: ID_TOKEN,
      clientEntityId: CLIENT_ENTITY_ID,
    })

    await expect(pending.complete()).rejects.toThrow()

    const authKey = await store.resolveOrCreate({
      appId: 'app-123',
      environment: 'sandbox',
      clientEntityId: CLIENT_ENTITY_ID,
    })
    expect(authKey.resolution()).toBe('created')
  })

  it('fails closed rather than acknowledging the AuthKey when status is absent but an expiresAt is present', async () => {
    const { client, store } = ceremonyClient([
      jsonResponse(201, PREPARED),
      jsonResponse(200, SESSION),
      jsonResponse(200, ACTIVE_WITH_EXPIRES_AT_FIELD),
    ])
    const prepared = await client.prepareSocialLogin({ provider: 'GOOGLE' })
    const pending = await prepared.completeSocialSession({
      idToken: ID_TOKEN,
      clientEntityId: CLIENT_ENTITY_ID,
    })

    await expect(pending.complete()).rejects.toThrow()

    const authKey = await store.resolveOrCreate({
      appId: 'app-123',
      environment: 'sandbox',
      clientEntityId: CLIENT_ENTITY_ID,
    })
    expect(authKey.resolution()).toBe('created')
  })

  // Complete spends a single-use registration handle, so the same pending
  // registration is never sent twice, even after a successful first call.
  it('is one-shot: a second complete() is rejected without another request', async () => {
    const { client, transport } = ceremonyClient([
      jsonResponse(201, PREPARED),
      jsonResponse(200, SESSION),
      jsonResponse(200, ACTIVE),
    ])
    const prepared = await client.prepareSocialLogin({ provider: 'GOOGLE' })
    const pending = await prepared.completeSocialSession({
      idToken: ID_TOKEN,
      clientEntityId: CLIENT_ENTITY_ID,
    })
    const result = await pending.complete()
    expect(result.status).toBe('ACTIVE')
    expect(transport.sent).toHaveLength(3)

    const retry: unknown = await pending.complete().catch((err: unknown) => err)
    expect(isDaaError(retry)).toBe(true)
    if (isDaaError(retry)) {
      expect(retry.detail.kind).toBe('contract_violation')
    }
    expect((retry as Error).message).toMatch(/already been consumed/)
    expect(transport.sent).toHaveLength(3)
  })
})

describe('DaaClient.forUser', () => {
  it('opens the operations surface only for an ACTIVE context', async () => {
    const { client } = ceremonyClient([
      jsonResponse(201, PREPARED),
      jsonResponse(200, SESSION),
      jsonResponse(200, ACTIVE),
    ])
    const prepared = await client.prepareSocialLogin({ provider: 'GOOGLE' })
    const pending = await prepared.completeSocialSession({
      idToken: ID_TOKEN,
      clientEntityId: CLIENT_ENTITY_ID,
    })
    const result = await pending.complete()
    if (result.status !== 'ACTIVE') {
      throw new Error('expected ACTIVE')
    }

    const transport: DaaTransport = {
      async send() {
        return { status: 200, headers: {}, bodyBytes: null }
      },
    }
    const daa = new DaaClient({
      appId: 'app-123',
      environment: 'sandbox',
      transport,
      keyPolicy: DEVICE_KEY_POLICY,
    })
    const user = daa.forUser(result.context)
    expect(user.accounts).toBeDefined()
    expect(() => daa.forUser({} as never)).toThrow(/ACTIVE DaaUserContext/)
  })

  it('carries publicApiOrigin into the surface as the pagination trust anchor', async () => {
    const { client } = ceremonyClient([
      jsonResponse(201, PREPARED),
      jsonResponse(200, SESSION),
      jsonResponse(200, ACTIVE),
    ])
    const prepared = await client.prepareSocialLogin({ provider: 'GOOGLE' })
    const pending = await prepared.completeSocialSession({
      idToken: ID_TOKEN,
      clientEntityId: CLIENT_ENTITY_ID,
    })
    const result = await pending.complete()
    if (result.status !== 'ACTIVE') {
      throw new Error('expected ACTIVE')
    }

    const publicApiOrigin = 'https://api-test.circle.com'
    const page = new TextEncoder().encode('{"data":[]}')
    const transport = new ScriptedTransport([
      {
        status: 200,
        headers: { Link: `<${publicApiOrigin}/v1/accounts?pageAfter=x>; rel="next"` },
        bodyBytes: page,
      },
      { status: 200, headers: {}, bodyBytes: page },
    ])
    const daa = new DaaClient({
      appId: 'app-123',
      environment: 'sandbox',
      transport,
      keyPolicy: DEVICE_KEY_POLICY,
      publicApiOrigin,
    })
    const first = await daa.forUser(result.context).accounts.list()
    await first.next()
    expect(transport.sent[1]?.query).toBe('pageAfter=x')
  })

  /**
   * End to end on the production path: hand an ACTIVE context to `forUser`,
   * and perform an authorized write signed by the real native AuthKey store.
   * It is written against the native `DaaSecureKey` module rather than an
   * injected store because what it pins is the wiring — if `forUser` validated
   * the context and then built the operations surface without it, every write
   * would have no credential to sign with and none of the read tests could
   * notice.
   *
   * The native `DaaSecureKey` mock is used by both registration completion and
   * the later DaaClient, so the context's local thumbprint binding is the same
   * one the signed operation resolves. The registration-flow key remains
   * WebCrypto here because the test does not exercise the native flow-key
   * provider.
   */
  it('signs a create with the context authKeyId and the AuthKey that login resolved', async () => {
    const requireNative = jest.mocked(requireOptionalNativeModule)
    const previous = requireNative.getMockImplementation()
    const keyPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
      'sign',
      'verify',
    ])
    let resolveCalls = 0
    const signWithKey = async (signingInputBase64Url: string): Promise<string> =>
      toBase64Url(
        new Uint8Array(
          await crypto.subtle.sign(
            { name: 'ECDSA', hash: 'SHA-256' },
            keyPair.privateKey,
            toArrayBuffer(fromBase64Url(signingInputBase64Url)),
          ),
        ),
      )
    requireNative.mockImplementation((name: string) => {
      if (name === 'DaaSecureKey') {
        return {
          declaredKeyPolicy: () => DEVICE_KEY_POLICY,
          resolveOrCreate: async () => {
            resolveCalls += 1
            return 'existing'
          },
          publicKeySpkiBase64Url: async () =>
            toBase64Url(new Uint8Array(await crypto.subtle.exportKey('spki', keyPair.publicKey))),
          acknowledgeRegistration: async () => undefined,
          signDeviceAuthorization: async (
            _appId: string,
            _environment: string,
            signingInputBase64Url: string,
          ) => signWithKey(signingInputBase64Url),
          signRegistrationDeviceAuthorization: async (
            _appId: string,
            _environment: string,
            signingInputBase64Url: string,
          ) => signWithKey(signingInputBase64Url),
        }
      }
      return previous?.(name) ?? null
    })

    try {
      const authTransport = new ScriptedTransport([
        jsonResponse(201, PREPARED),
        jsonResponse(200, SESSION),
        jsonResponse(200, ACTIVE),
      ])
      const authClient = new AuthClient({
        transport: authTransport,
        registrationFlowKeys: webCryptoRegistrationFlowKeyProvider(),
        identity: { appId: 'app-123', environment: 'sandbox' },
      })
      const prepared = await authClient.prepareSocialLogin({ provider: 'GOOGLE' })
      const pending = await prepared.completeSocialSession({
        idToken: ID_TOKEN,
        clientEntityId: CLIENT_ENTITY_ID,
      })
      const result = await pending.complete()
      if (result.status !== 'ACTIVE') {
        throw new Error('expected ACTIVE')
      }

      const transport = new ScriptedTransport([
        jsonResponse(
          201,
          '{"accountId":"acct-1","balances":[],"entityId":"e","purpose":"custody",' +
            '"status":"pending","type":"first_party","custodyType":"self"}',
        ),
      ])
      const daa = new DaaClient({
        appId: 'app-123',
        environment: 'sandbox',
        transport,
        keyPolicy: DEVICE_KEY_POLICY,
      })

      const account = await daa.forUser(result.context).accounts.create({
        idempotencyKey: '22222222-2222-4222-a222-222222222222',
        clientEntityId: CLIENT_ENTITY_ID,
        custodyType: 'self',
        type: 'third_party',
        purpose: 'custody',
        description: 'Primary',
        blockchain: 'ARC',
      })

      expect(account.accountId).toBe('acct-1')
      const create = transport.sent[0]
      if (create === undefined) {
        throw new Error('expected a create request')
      }
      expect(create.method).toBe('POST')
      expect(create.path).toBe('/v1/accounts')
      const compact = create.headers[DEVICE_AUTHORIZATION_HEADER]
      if (compact === undefined) {
        throw new Error('expected a device authorization on the create')
      }
      const header: unknown = JSON.parse(
        new TextDecoder().decode(fromBase64Url(compact.split('.')[0] ?? '')),
      )
      const claims: unknown = JSON.parse(
        new TextDecoder().decode(fromBase64Url(compact.split('.')[1] ?? '')),
      )
      // The `kid` is the service-assigned id from the ACTIVE DeviceContext, not
      // a fresh one the SDK made up — that is the value being carried through.
      expect(header).toMatchObject({ kid: AUTH_KEY_ID })
      expect(claims).toMatchObject({
        canonical_path: '/v1/accounts',
        discriminator: 'create_account',
      })
      // AuthClient and DaaClient each have a JS resolver, but both resolve the
      // same native key identity; the thumbprint check is what ties the context
      // and the later JWS kid together across those two handles.
      expect(resolveCalls).toBe(2)
    } finally {
      requireNative.mockImplementation(previous ?? (() => null))
    }
  })

  /**
   * A real `DaaClient`'s registration-flow key comes from the native
   * `DaaRegistration` module by default. That module's flow-key
   * `signRegistrationAuthorization` is bridged on both platforms (see
   * `RegistrationFlowKey.ts`), but this suite's `jest.setup.js` fake does not
   * implement it, so Complete on the production path still fails closed here
   * rather than silently succeeding without the flow-key proof — pinning that
   * a missing native sign method is caught, not silently swallowed.
   */
  it('fails closed at Complete when the native registration-flow key cannot sign', async () => {
    // Just enough native DaaSecureKey to get through AuthKey selection at
    // Social Session; the point of this test is the flow-key sign step in
    // Complete, not AuthKey behavior.
    const requireNative = jest.mocked(requireOptionalNativeModule)
    const previous = requireNative.getMockImplementation()
    const keyPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
      'sign',
      'verify',
    ])
    requireNative.mockImplementation((name: string) => {
      if (name === 'DaaSecureKey') {
        return {
          declaredKeyPolicy: () => DEVICE_KEY_POLICY,
          resolveOrCreate: async () => 'created',
          publicKeySpkiBase64Url: async () =>
            toBase64Url(new Uint8Array(await crypto.subtle.exportKey('spki', keyPair.publicKey))),
          acknowledgeRegistration: async () => undefined,
          signDeviceAuthorization: async () => {
            throw new Error('signDeviceAuthorization should not be reached in this test')
          },
        }
      }
      return previous?.(name) ?? null
    })

    try {
      const transport = new ScriptedTransport([
        jsonResponse(201, PREPARED),
        jsonResponse(200, SESSION),
      ])
      const daa = new DaaClient({
        appId: 'app-123',
        environment: 'sandbox',
        transport,
        keyPolicy: DEVICE_KEY_POLICY,
      })
      const prepared = await daa.auth.prepareSocialLogin({ provider: 'GOOGLE' })
      const pending = await prepared.completeSocialSession({
        idToken: ID_TOKEN,
        clientEntityId: CLIENT_ENTITY_ID,
      })
      const error: unknown = await pending.complete().catch((err: unknown) => err)

      expect(isDaaError(error)).toBe(true)
      if (isDaaError(error)) {
        expect(error.detail.kind).toBe('contract_violation')
      }
      expect((error as Error).message).toMatch(/signRegistrationAuthorization is required/)
    } finally {
      requireNative.mockImplementation(previous ?? (() => null))
    }
  })
})
