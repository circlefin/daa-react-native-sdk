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

import type { DeviceContext } from '../models/DaaUserContext'
import { isUuid } from '../validation/uuid'
import { requiredDateTime } from './instant'
import { asObject, MalformedPayloadError, requiredString } from './payload'

function requiredUuidField(payload: Record<string, unknown>, name: string): string {
  const value = requiredString(payload, name)
  if (!isUuid(value)) {
    throw new MalformedPayloadError(name)
  }
  return value
}

/**
 * Decode the wire `DeviceContext`: the shape Device Registration
 * Complete's `context` carries and `get_device_context`
 * (`GET /v1/accounts/auth/context`, `DaaUserClient.refreshContext`) returns.
 *
 * One decoder for both, rather than two copies: they are the same
 * `DeviceContext` response type, so a divergence between "the shape Complete
 * returns" and "the shape refresh returns" would be a service defect, not
 * something two independent decoders should each get to interpret.
 *
 * `DeviceContext.resolvedAt` is one of the timestamps the service sends in its
 * default number form, the same as `PreparedSocialLogin.expiresAt`, so the
 * epoch-millisecond form is accepted here. See `wire/instant.ts`.
 */
export function toDeviceContext(value: unknown): DeviceContext {
  const payload = asObject(value, 'deviceContext')
  const status = requiredString(payload, 'deviceCredentialStatus')
  if (status !== 'active') {
    throw new MalformedPayloadError('deviceCredentialStatus')
  }
  return {
    deviceCredentialStatus: 'active',
    ownerBindingId: requiredUuidField(payload, 'ownerBindingId'),
    authKeyId: requiredUuidField(payload, 'authKeyId'),
    resolvedAt: requiredDateTime(payload, 'resolvedAt'),
  }
}
