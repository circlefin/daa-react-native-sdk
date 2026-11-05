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

import { toDeviceRegistrationResult } from '../wire/deviceRegistrationResultPayload'
import { MalformedPayloadError } from '../wire/payload'

const CLIENT_ENTITY_ID = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
const OWNER_BINDING_ID = '11111111-2222-4333-8444-555555555555'
const AUTH_KEY_ID = '99999999-8888-4777-8666-555555555555'
const RESOLVED_AT = '2026-08-26T12:00:00Z'

function flatPayload(extra: Record<string, unknown>): Record<string, unknown> {
  return {
    deviceCredentialStatus: 'active',
    ownerBindingId: OWNER_BINDING_ID,
    authKeyId: AUTH_KEY_ID,
    resolvedAt: RESOLVED_AT,
    ...extra,
  }
}

describe('toDeviceRegistrationResult — RECOVERY_PENDING-signal rejection on the flat shape', () => {
  it('names the offending recoveryReference field, not status', () => {
    const payload = flatPayload({ recoveryReference: 'r'.repeat(16) })

    let thrown: unknown
    try {
      toDeviceRegistrationResult(payload, CLIENT_ENTITY_ID)
    } catch (err) {
      thrown = err
    }

    expect(thrown).toBeInstanceOf(MalformedPayloadError)
    // `status` is absent on this payload, not malformed — the field that
    // actually made the payload ambiguous is `recoveryReference`.
    expect((thrown as MalformedPayloadError).fieldName).toBe('recoveryReference')
  })

  it('names the offending expiresAt field, not status', () => {
    const payload = flatPayload({ expiresAt: RESOLVED_AT })

    let thrown: unknown
    try {
      toDeviceRegistrationResult(payload, CLIENT_ENTITY_ID)
    } catch (err) {
      thrown = err
    }

    expect(thrown).toBeInstanceOf(MalformedPayloadError)
    expect((thrown as MalformedPayloadError).fieldName).toBe('expiresAt')
  })

  it('still decodes the flat shape when neither RECOVERY_PENDING field is present', () => {
    const payload = flatPayload({})
    const result = toDeviceRegistrationResult(payload, CLIENT_ENTITY_ID)
    expect(result.status).toBe('ACTIVE')
  })
})
