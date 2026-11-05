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

import { requireOwnerGrantFlowKeyThumbprint } from '../auth/ownerGrant'
import { toBase64Url } from '../crypto/base64url'
import { isDaaError } from '../errors'
import { MalformedPayloadError } from '../wire/payload'
import { toPendingRegistration } from '../wire/pendingRegistrationPayload'
import { toDeviceRegistrationResult } from '../wire/deviceRegistrationResultPayload'

const HANDLE = 'h'.repeat(32)
const EXPIRES_AT = '2026-08-26T12:00:00Z'
const UUID = '3f1a2b4c-5d6e-4f70-8192-a3b4c5d6e7f8'

/**
 * The epoch-millisecond form the service sends some timestamps in, and the
 * exact instant it has to normalise to.
 *
 * The number is a Prepare `expiresAt` value in the service's wire form.
 * `SocialSession` and `DeviceContext` are the same kind of field, serialised
 * the same way; these cases assert the decoder's tolerance, not the service's
 * behaviour.
 */
const EPOCH_MILLIS = 1788290024580
const EPOCH_MILLIS_ISO = '2026-09-01T19:13:44.580Z'

/** Numbers that are not a plausible count of epoch milliseconds. */
const BAD_EPOCHS = [
  1788290024580.5, // fractional
  -1788290024580, // negative
  0, // the epoch itself is a dropped field, not a timestamp
  8.64e15 + 1, // past the largest instant `Date` represents
  1e15, // renders a year the ISO-8601 grammar cannot spell
  Number.NaN,
  Number.POSITIVE_INFINITY,
  Number.MAX_SAFE_INTEGER,
]

/**
 * Text that is not the ISO-8601 form. The first is the epoch *as a string*: the
 * tolerance is for a JSON number, so quoting it does not buy it a pass.
 */
const BAD_DATE_TEXT = ['1788290024580', '2026-08-26 12:00:00Z', '2026-08-26', '', 'not-a-date']

function session(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    registrationHandle: HANDLE,
    clientEntityId: UUID,
    expiresAt: EXPIRES_AT,
    ...overrides,
  }
}

function compactJwt(payload: object): string {
  const header = toBase64Url(new TextEncoder().encode('{"alg":"ES256"}'))
  const body = toBase64Url(new TextEncoder().encode(JSON.stringify(payload)))
  return `${header}.${body}.c2ln`
}

describe('toPendingRegistration', () => {
  it('reads the SocialSession fields', () => {
    expect(
      toPendingRegistration({
        registrationHandle: HANDLE,
        clientEntityId: UUID,
        expiresAt: EXPIRES_AT,
      }),
    ).toEqual({
      registrationHandle: HANDLE,
      clientEntityId: UUID,
      expiresAt: EXPIRES_AT,
      ownerGrant: null,
    })
  })

  it('captures ownerGrant when present without treating it as verified', () => {
    const grant = compactJwt({ registrationFlowKeyThumbprint: 'a'.repeat(43) })
    expect(
      toPendingRegistration({
        registrationHandle: HANDLE,
        clientEntityId: UUID,
        expiresAt: EXPIRES_AT,
        ownerGrant: grant,
      }).ownerGrant,
    ).toBe(grant)
  })

  it('takes either wire form for expiresAt and hands on one normalised instant', () => {
    // Pinned to the instant, not to an ISO *shape*: a seconds-vs-milliseconds
    // misreading, or an off-by-one, still produces a well-formed timestamp.
    expect(toPendingRegistration(session({ expiresAt: EPOCH_MILLIS })).expiresAt).toBe(
      EPOCH_MILLIS_ISO,
    )
    expect(toPendingRegistration(session({ expiresAt: 1 })).expiresAt).toBe(
      '1970-01-01T00:00:00.001Z',
    )
    // The string form, which the contract declares, is passed through untouched;
    // only the number form is normalised.
    expect(toPendingRegistration(session({ expiresAt: EXPIRES_AT })).expiresAt).toBe(EXPIRES_AT)
  })

  it('rejects an expiresAt that is neither wire form', () => {
    for (const expiresAt of [...BAD_EPOCHS, ...BAD_DATE_TEXT]) {
      expect(() => toPendingRegistration(session({ expiresAt }))).toThrow(MalformedPayloadError)
    }
  })

  it('rejects a handle outside the contract bounds or a non-UUID clientEntityId', () => {
    expect(() =>
      toPendingRegistration({
        registrationHandle: '',
        clientEntityId: UUID,
        expiresAt: EXPIRES_AT,
      }),
    ).toThrow(MalformedPayloadError)
    expect(() =>
      toPendingRegistration({
        registrationHandle: 'h'.repeat(201),
        clientEntityId: UUID,
        expiresAt: EXPIRES_AT,
      }),
    ).toThrow(MalformedPayloadError)
    expect(() =>
      toPendingRegistration({
        registrationHandle: HANDLE,
        clientEntityId: 'not-a-uuid',
        expiresAt: EXPIRES_AT,
      }),
    ).toThrow(MalformedPayloadError)
  })
})

describe('requireOwnerGrantFlowKeyThumbprint', () => {
  const thumbprint = 'b'.repeat(43)

  it('fails closed when the claim is missing and never interpolates the grant', () => {
    const grant = compactJwt({ sub: 'GRANT_SECRET' })
    try {
      requireOwnerGrantFlowKeyThumbprint(grant, thumbprint, null)
    } catch (err) {
      expect(isDaaError(err)).toBe(true)
      expect((err as Error).message).toMatch(/registrationFlowKeyThumbprint/)
      expect((err as Error).message).not.toMatch(/GRANT_SECRET/)
      return
    }
    throw new Error('expected fail-closed')
  })

  it('fails closed when the thumbprint does not match the flow key', () => {
    const grant = compactJwt({ registrationFlowKeyThumbprint: 'c'.repeat(43) })
    expect(() => requireOwnerGrantFlowKeyThumbprint(grant, thumbprint, null)).toThrow(
      /does not match/,
    )
  })

  it('accepts an exact matching thumbprint', () => {
    const grant = compactJwt({ registrationFlowKeyThumbprint: thumbprint })
    expect(() => requireOwnerGrantFlowKeyThumbprint(grant, thumbprint, null)).not.toThrow()
  })
})

describe('toDeviceRegistrationResult', () => {
  const deviceContext = {
    deviceCredentialStatus: 'active',
    ownerBindingId: UUID,
    authKeyId: UUID,
    resolvedAt: EXPIRES_AT,
  }

  function resolvedAtOf(payload: Record<string, unknown>): string {
    const result = toDeviceRegistrationResult(payload, UUID)
    if (result.status !== 'ACTIVE') {
      throw new Error('expected ACTIVE')
    }
    return result.context.deviceContext.resolvedAt
  }

  function recoveryPending(expiresAt: unknown): Record<string, unknown> {
    return { status: 'RECOVERY_PENDING', recoveryReference: 'r'.repeat(16), expiresAt }
  }

  function recoveryExpiresAt(expiresAt: unknown): string {
    const result = toDeviceRegistrationResult(recoveryPending(expiresAt), UUID)
    if (result.status !== 'RECOVERY_PENDING') {
      throw new Error('expected RECOVERY_PENDING')
    }
    return result.expiresAt
  }

  it('decodes a flat DeviceContext as ACTIVE', () => {
    const result = toDeviceRegistrationResult(deviceContext, UUID)
    expect(result.status).toBe('ACTIVE')
    if (result.status === 'ACTIVE') {
      expect(result.context.clientEntityId).toBe(UUID)
      expect(result.context.deviceContext.deviceCredentialStatus).toBe('active')
    }
  })

  it('takes either wire form for resolvedAt and hands on one normalised instant', () => {
    // Pinned to the instant, not to an ISO *shape*: a seconds-vs-milliseconds
    // misreading, or an off-by-one, still produces a well-formed timestamp.
    expect(resolvedAtOf({ ...deviceContext, resolvedAt: EPOCH_MILLIS })).toBe(EPOCH_MILLIS_ISO)
    expect(resolvedAtOf({ ...deviceContext, resolvedAt: 1 })).toBe('1970-01-01T00:00:00.001Z')
    // The string form is passed through untouched.
    expect(resolvedAtOf(deviceContext)).toBe(EXPIRES_AT)
  })

  it('rejects a resolvedAt that is neither wire form', () => {
    for (const resolvedAt of [...BAD_EPOCHS, ...BAD_DATE_TEXT]) {
      expect(() => toDeviceRegistrationResult({ ...deviceContext, resolvedAt }, UUID)).toThrow(
        MalformedPayloadError,
      )
    }
  })

  it('ignores extra response fields on a flat DeviceContext', () => {
    const result = toDeviceRegistrationResult({ ...deviceContext, extra: 1 }, UUID)
    expect(result.status).toBe('ACTIVE')
  })

  it('decodes a wrapped ACTIVE into a nominal DaaUserContext', () => {
    const result = toDeviceRegistrationResult(
      {
        status: 'ACTIVE',
        context: {
          clientEntityId: UUID,
          deviceContext,
        },
      },
      UUID,
    )
    expect(result.status).toBe('ACTIVE')
    if (result.status === 'ACTIVE') {
      expect(result.context.clientEntityId).toBe(UUID)
      expect(result.context.deviceContext.deviceCredentialStatus).toBe('active')
    }
  })

  it('rejects a context minted via ctx.constructor for a different Owner', () => {
    // `isActiveDaaUserContext`'s `instanceof` + `#active` check stops a
    // consumer-fabricated object literal, but that alone does not stop the
    // class itself: anything holding one real ACTIVE context can reach
    // `DaaUserContext` through `ctx.constructor`, with no import of this
    // module at all. The constructor is brand-gated, so calling it that way
    // throws instead of minting a second ACTIVE context for a different Owner.
    const result = toDeviceRegistrationResult(
      {
        status: 'ACTIVE',
        context: { clientEntityId: UUID, deviceContext },
      },
      UUID,
    )
    if (result.status !== 'ACTIVE') {
      throw new Error('expected ACTIVE')
    }
    const forgedOwnerId = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
    const Ctor = result.context.constructor as new (...args: unknown[]) => unknown

    let thrown: unknown
    try {
      new Ctor({
        clientEntityId: forgedOwnerId,
        deviceContext: { ...deviceContext, ownerBindingId: forgedOwnerId },
      })
    } catch (err) {
      thrown = err
    }

    expect(isDaaError(thrown)).toBe(true)
  })

  it('rejects a wrapped ACTIVE whose clientEntityId diverges from Social Session', () => {
    expect(() =>
      toDeviceRegistrationResult(
        {
          status: 'ACTIVE',
          context: {
            clientEntityId: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
            deviceContext,
          },
        },
        UUID,
      ),
    ).toThrow(MalformedPayloadError)
  })

  it('decodes RECOVERY_PENDING without a context', () => {
    const result = toDeviceRegistrationResult(
      {
        status: 'RECOVERY_PENDING',
        recoveryReference: 'r'.repeat(16),
        expiresAt: EXPIRES_AT,
      },
      UUID,
    )
    expect(result.status).toBe('RECOVERY_PENDING')
  })

  it('takes either wire form for a RECOVERY_PENDING expiresAt', () => {
    expect(recoveryExpiresAt(EPOCH_MILLIS)).toBe(EPOCH_MILLIS_ISO)
    expect(recoveryExpiresAt(1)).toBe('1970-01-01T00:00:00.001Z')
    expect(recoveryExpiresAt(EXPIRES_AT)).toBe(EXPIRES_AT)
  })

  it('rejects a RECOVERY_PENDING expiresAt that is neither wire form', () => {
    for (const expiresAt of [...BAD_EPOCHS, ...BAD_DATE_TEXT]) {
      expect(() => toDeviceRegistrationResult(recoveryPending(expiresAt), UUID)).toThrow(
        MalformedPayloadError,
      )
    }
  })

  it('rejects an unknown status rather than degrading', () => {
    expect(() => toDeviceRegistrationResult({ status: 'PENDING' }, UUID)).toThrow(
      MalformedPayloadError,
    )
  })

  it('rejects RECOVERY_PENDING that also carries a context', () => {
    expect(() =>
      toDeviceRegistrationResult(
        {
          status: 'RECOVERY_PENDING',
          recoveryReference: 'r'.repeat(16),
          expiresAt: EXPIRES_AT,
          context: { clientEntityId: UUID },
        },
        UUID,
      ),
    ).toThrow(MalformedPayloadError)
  })
})
