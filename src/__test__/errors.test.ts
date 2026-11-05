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

import {
  contractViolation,
  idempotencyConflict,
  isDaaError,
  loginRequestExpired,
  mapNativeError,
  prepareReceiptInvalid,
  withRequestId,
} from '../errors'

describe('the login-attempt errors', () => {
  it('models an expired login request without inventing a retry hint', () => {
    const err = loginRequestExpired(null)
    expect(err.detail).toEqual({ kind: 'login_request_expired' })
    // The recovery is a new prepare, not a retry, so there is no `retryable` flag
    // for a caller to misread.
    expect(err.detail).not.toHaveProperty('retryable')
  })

  it('models an invalid Prepare receipt as its own kind, keeping the cause off the detail', () => {
    const cause = new Error('native detail')
    const err = prepareReceiptInvalid('the Prepare receipt has expired', cause)
    expect(err.detail).toEqual({ kind: 'prepare_receipt_invalid' })
    // The recovery is a new prepare, not a retry of this one.
    expect(err.detail).not.toHaveProperty('retryable')
    expect(err.message).toBe('DAA: the Prepare receipt has expired')
    expect(err.cause).toBe(cause)
  })

  it('can attach a correlation id to a contract violation without interpolating a JWS', () => {
    const err = contractViolation('the device authorization was replayed', 'req-1')
    expect(err.detail).toEqual({ kind: 'contract_violation', correlationId: 'req-1' })
    expect(err.message).toMatch(/requestId=req-1/)
    expect(err.message).not.toMatch(/eyJ/)
  })

  it('carries the conflicting idempotency key on the detail but not in the message', () => {
    const err = idempotencyConflict('22222222-2222-4222-a222-222222222222', null)
    expect(err.detail).toEqual({
      kind: 'idempotency_conflict',
      idempotencyKey: '22222222-2222-4222-a222-222222222222',
    })
    expect(err.message).not.toMatch(/22222222/)
  })
})

describe('a request id with control characters', () => {
  // The id comes from a response header and reaches `message`, which an app
  // logs; CR/LF there could forge a log line.
  const HOSTILE = 'abc\r\ndef\u0007'

  it.each([
    ['loginRequestExpired', () => loginRequestExpired(HOSTILE)],
    [
      'idempotencyConflict',
      () => idempotencyConflict('22222222-2222-4222-a222-222222222222', HOSTILE),
    ],
    [
      'withRequestId',
      () => withRequestId(prepareReceiptInvalid('the Prepare receipt has expired'), HOSTILE),
    ],
  ])('%s keeps only printable ASCII in the message', (_name, build) => {
    const err = build()
    expect(err.message.endsWith(' (requestId=abcdef)')).toBe(true)
    expect(err.message).not.toMatch(/[^\x20-\x7e]/)
  })

  it('keeps the exact id on the idempotency_conflict detail', () => {
    const err = idempotencyConflict('22222222-2222-4222-a222-222222222222', HOSTILE)
    expect(err.detail).toHaveProperty('correlationId', HOSTILE)
  })
})

describe('withRequestId', () => {
  it('names the id in the message and keeps the kind, the cause and the stack', () => {
    const cause = new Error('verifier detail')
    const original = prepareReceiptInvalid('the Prepare receipt has expired', cause)
    const err = withRequestId(original, 'req-1')
    expect(err.detail).toEqual({ kind: 'prepare_receipt_invalid' })
    expect(err.message).toBe('DAA: the Prepare receipt has expired (requestId=req-1)')
    expect(err.cause).toBe(cause)
    // The frames are the original throw site's, not this wrapper's.
    const frames = (stack: string | undefined) => (stack ?? '').split('\n').slice(1)
    expect(frames(err.stack)).toEqual(frames(original.stack))
    expect(err.stack?.split('\n')[0]).toContain('(requestId=req-1)')
  })

  it('puts a request id holding replace patterns into the stack literally', () => {
    const original = prepareReceiptInvalid('the Prepare receipt has expired')
    const err = withRequestId(original, "a$'b$&c$$d")
    expect(err.message).toBe("DAA: the Prepare receipt has expired (requestId=a$'b$&c$$d)")
    expect(err.stack?.split('\n')[0]).toBe(`DaaError: ${err.message}`)
  })
})

describe('mapNativeError', () => {
  it('maps the two custody codes to their kinds and keeps native text out of message', () => {
    const auth = mapNativeError(
      Object.assign(new Error('SecItemCopyMatching OSStatus -25293'), {
        code: 'USER_AUTH_REQUIRED',
      }),
    )
    expect(auth.detail.kind).toBe('local_user_authentication_required')
    expect(auth.message).not.toMatch(/OSStatus/)

    const init = mapNativeError(
      Object.assign(new Error('keystore uninitialized'), { code: 'NOT_INITIALIZED' }),
    )
    expect(init.detail.kind).toBe('device_not_initialized')

    expect(mapNativeError(new Error('anything else')).detail.kind).toBe('contract_violation')
    expect(mapNativeError(undefined).detail.kind).toBe('contract_violation')
  })

  it('passes an already-structured DaaError through unchanged', () => {
    const original = contractViolation('already mapped')
    expect(mapNativeError(original)).toBe(original)
  })

  it('retains the cause but does not export it through serialization', () => {
    const native = Object.assign(
      new Error('AndroidKeyStore: KM_ERROR_KEY_USER_NOT_AUTHENTICATED'),
      {
        code: 'X',
        nativeStackAndroid: ['at com.example.Keystore.sign'],
      },
    )
    const err = mapNativeError(native)
    expect(isDaaError(err)).toBe(true)
    expect(err.cause).toBe(native) // available to a host that deliberately inspects
    // The raw native internals must not reach a serialized/exported form.
    expect(JSON.stringify(err)).not.toMatch(/KM_ERROR|nativeStackAndroid/)
  })
})
