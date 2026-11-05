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

import { toDeviceContext } from '../wire/deviceContextPayload'
import { MalformedPayloadError } from '../wire/payload'

const UUID = '3f1a2b4c-5d6e-4f70-8192-a3b4c5d6e7f8'
const OTHER_UUID = '11111111-1111-4111-8111-111111111111'
const RESOLVED_AT = '2026-08-26T12:00:00Z'

/**
 * The epoch-millisecond form the service sends some timestamps in, and the
 * exact instant it has to normalise to. Mirrors `loginPayload.test.ts`'s
 * constant: `DeviceContext` is one of the three login-flow responses that use
 * that form, per `wire/instant.ts`.
 */
const EPOCH_MILLIS = 1788290024580
const EPOCH_MILLIS_ISO = '2026-09-01T19:13:44.580Z'

const BAD_EPOCHS = [
  1788290024580.5, // fractional
  -1788290024580, // negative
  0, // the epoch itself is a dropped field, not a timestamp
  Number.NaN,
  Number.POSITIVE_INFINITY,
]

const BAD_DATE_TEXT = ['1788290024580', '2026-08-26 12:00:00Z', '2026-08-26', '', 'not-a-date']

const COMPLETE = Object.freeze({
  deviceCredentialStatus: 'active',
  ownerBindingId: UUID,
  authKeyId: OTHER_UUID,
  resolvedAt: RESOLVED_AT,
})

function decode(overrides: Record<string, unknown> = {}) {
  return toDeviceContext({ ...COMPLETE, ...overrides })
}

describe('toDeviceContext', () => {
  it('decodes the exact GET /v1/accounts/auth/context shape', () => {
    expect(decode()).toEqual({
      deviceCredentialStatus: 'active',
      ownerBindingId: UUID,
      authKeyId: OTHER_UUID,
      resolvedAt: RESOLVED_AT,
    })
  })

  it('ignores an extra response field rather than failing the response', () => {
    expect(decode({ clientEntityId: UUID })).toEqual({
      deviceCredentialStatus: 'active',
      ownerBindingId: UUID,
      authKeyId: OTHER_UUID,
      resolvedAt: RESOLVED_AT,
    })
  })

  it('rejects a deviceCredentialStatus other than the one defined value', () => {
    for (const bad of ['inactive', 'ACTIVE', '', null, 1]) {
      expect(() => decode({ deviceCredentialStatus: bad })).toThrow(MalformedPayloadError)
    }
  })

  it('rejects a non-UUID ownerBindingId or authKeyId', () => {
    for (const bad of ['', 'not-a-uuid', OTHER_UUID + 'x']) {
      expect(() => decode({ ownerBindingId: bad })).toThrow(MalformedPayloadError)
      expect(() => decode({ authKeyId: bad })).toThrow(MalformedPayloadError)
    }
  })

  it('accepts a UUID in either case', () => {
    expect(decode({ authKeyId: OTHER_UUID.toUpperCase() }).authKeyId).toBe(OTHER_UUID.toUpperCase())
  })

  it('takes either wire form for resolvedAt and hands on one normalised instant', () => {
    // Pinned to the instant, not to an ISO *shape*: a seconds-vs-milliseconds
    // misreading, or an off-by-one, still produces a well-formed timestamp.
    expect(decode({ resolvedAt: EPOCH_MILLIS }).resolvedAt).toBe(EPOCH_MILLIS_ISO)
    expect(decode({ resolvedAt: 1 }).resolvedAt).toBe('1970-01-01T00:00:00.001Z')
    // The string form is passed through untouched.
    expect(decode({ resolvedAt: RESOLVED_AT }).resolvedAt).toBe(RESOLVED_AT)
  })

  it('rejects a resolvedAt that is neither wire form', () => {
    for (const resolvedAt of [...BAD_EPOCHS, ...BAD_DATE_TEXT]) {
      expect(() => decode({ resolvedAt })).toThrow(MalformedPayloadError)
    }
  })

  it('rejects a value that is not an object', () => {
    for (const bad of [null, undefined, 'text', 1, [], true]) {
      expect(() => toDeviceContext(bad)).toThrow(MalformedPayloadError)
    }
  })

  it('rejects a payload missing a guaranteed field', () => {
    for (const key of ['deviceCredentialStatus', 'ownerBindingId', 'authKeyId', 'resolvedAt']) {
      const rest: Record<string, unknown> = { ...COMPLETE }
      delete rest[key]
      expect(() => toDeviceContext(rest)).toThrow(MalformedPayloadError)
    }
  })
})
