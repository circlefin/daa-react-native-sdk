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
  DaaUserContext,
  DECODER_TOKEN,
  type DeviceRegistrationResult,
} from '../models/DaaUserContext'
import { toDeviceContext } from './deviceContextPayload'
import { requiredDateTime } from './instant'
import {
  asObject,
  MalformedPayloadError,
  optionalObject,
  optionalString,
  requiredString,
} from './payload'

const RECOVERY_REF_MIN = 16
const RECOVERY_REF_MAX = 512

function toActiveContext(
  payload: Record<string, unknown>,
  sessionClientEntityId: string,
): DaaUserContext {
  return new DaaUserContext(DECODER_TOKEN, {
    clientEntityId: sessionClientEntityId,
    deviceContext: toDeviceContext(payload),
  })
}

/**
 * The DeviceContext-shaped object Complete returns: a flat payload, or
 * nested `context.deviceContext` / `context` when `status: "ACTIVE"`.
 */
function deviceContextPayloadFromComplete(
  payload: Record<string, unknown>,
): Record<string, unknown> {
  if (optionalString(payload, 'status') !== 'ACTIVE') {
    return payload
  }
  const contextPayload = optionalObject(payload, 'context')
  if (contextPayload === null) {
    throw new MalformedPayloadError('context')
  }
  return optionalObject(contextPayload, 'deviceContext') ?? contextPayload
}

/**
 * Map Complete's `data` payload.
 *
 * The service returns a flat `DeviceContext`. The wrapped `{ status, context }`
 * shape and `RECOVERY_PENDING` are also decoded when present. An absent
 * `status` is read as that flat shape only on a positive signal: it still needs
 * `deviceCredentialStatus === 'active'` (enforced by `toDeviceContext`), and
 * it must carry neither `recoveryReference` nor `expiresAt` — the fields that
 * belong to the `RECOVERY_PENDING` shape. A payload carrying either alongside
 * an absent `status` is ambiguous and is rejected rather than resolved toward
 * the more privileged `ACTIVE` outcome. Extra members are otherwise ignored.
 * `clientEntityId` comes from Social Session, not this payload.
 */
export function toDeviceRegistrationResult(
  value: unknown,
  sessionClientEntityId: string,
): DeviceRegistrationResult {
  const payload = asObject(value, 'payload')
  const status = optionalString(payload, 'status')
  if (status === 'RECOVERY_PENDING') {
    if (optionalObject(payload, 'context') !== null) {
      throw new MalformedPayloadError('context')
    }
    const recoveryReference = requiredString(payload, 'recoveryReference')
    if (
      recoveryReference.length < RECOVERY_REF_MIN ||
      recoveryReference.length > RECOVERY_REF_MAX
    ) {
      throw new MalformedPayloadError('recoveryReference')
    }
    const result: DeviceRegistrationResult = Object.freeze({
      status: 'RECOVERY_PENDING',
      recoveryReference,
      // `expiresAt` accepts both timestamp forms, like the other login-flow
      // timestamps on this response.
      expiresAt: requiredDateTime(payload, 'expiresAt'),
    })
    return result
  }
  if (status === 'ACTIVE') {
    const contextPayload = optionalObject(payload, 'context')
    if (contextPayload === null) {
      throw new MalformedPayloadError('context')
    }
    const nestedClient = optionalString(contextPayload, 'clientEntityId')
    if (nestedClient !== null && nestedClient !== sessionClientEntityId) {
      throw new MalformedPayloadError('clientEntityId')
    }
    const devicePayload = deviceContextPayloadFromComplete(payload)
    const result: DeviceRegistrationResult = Object.freeze({
      status: 'ACTIVE',
      context: new DaaUserContext(DECODER_TOKEN, {
        clientEntityId: sessionClientEntityId,
        deviceContext: toDeviceContext(devicePayload),
      }),
    })
    return result
  }
  if (status !== null) {
    throw new MalformedPayloadError('status')
  }

  // Flat shape: only decodable on a positive ACTIVE signal, never on
  // the mere absence of `status`. `toActiveContext` still requires
  // `deviceCredentialStatus === 'active'`; this additionally refuses a
  // payload that also carries a `RECOVERY_PENDING` field, rather than
  // silently preferring the more privileged outcome. The error names
  // whichever `RECOVERY_PENDING` field is actually present — `status` itself
  // is absent here, not malformed.
  const conflictingRecoveryField = hasPresentField(payload, 'recoveryReference')
    ? 'recoveryReference'
    : hasPresentField(payload, 'expiresAt')
      ? 'expiresAt'
      : null
  if (conflictingRecoveryField !== null) {
    throw new MalformedPayloadError(conflictingRecoveryField)
  }

  const result: DeviceRegistrationResult = Object.freeze({
    status: 'ACTIVE',
    context: toActiveContext(payload, sessionClientEntityId),
  })
  return result
}

/** JSON `null` is treated as absence, matching `optionalString`/`optionalObject`. */
function hasPresentField(payload: Record<string, unknown>, name: string): boolean {
  const value = payload[name]
  return value !== undefined && value !== null
}
