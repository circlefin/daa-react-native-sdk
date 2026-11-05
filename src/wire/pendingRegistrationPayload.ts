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

import { isUuid } from '../validation/uuid'
import { requiredDateTime } from './instant'
import { asObject, MalformedPayloadError, optionalString, requiredString } from './payload'

/** The service caps `SocialSession.registrationHandle` at 200 characters. */
const HANDLE_MIN = 1
const HANDLE_MAX = 200

export type PendingRegistrationPayload = Readonly<{
  registrationHandle: string
  clientEntityId: string
  /** ISO-8601, normalised when the service sends epoch milliseconds instead. */
  expiresAt: string
  /**
   * Not part of the documented `SocialSession` response. When present, the SDK
   * checks it for a `registrationFlowKeyThumbprint` bound to this attempt's
   * flow key and fails closed if that is missing or does not match. Null when
   * the response does not carry it.
   */
  ownerGrant: string | null
}>

function requiredBounded(
  payload: Record<string, unknown>,
  name: string,
  min: number,
  max: number,
): string {
  const value = requiredString(payload, name)
  if (value.length < min || value.length > max) {
    throw new MalformedPayloadError(name)
  }
  return value
}

function requiredUuid(payload: Record<string, unknown>, name: string): string {
  const value = requiredString(payload, name)
  if (!isUuid(value)) {
    throw new MalformedPayloadError(name)
  }
  return value
}

/** Map the `SocialSession` body onto the fields the SDK keeps. */
export function toPendingRegistration(value: unknown): PendingRegistrationPayload {
  const payload = asObject(value, 'payload')
  const ownerGrant = optionalString(payload, 'ownerGrant')
  return {
    registrationHandle: requiredBounded(payload, 'registrationHandle', HANDLE_MIN, HANDLE_MAX),
    clientEntityId: requiredUuid(payload, 'clientEntityId'),
    // `SocialSession.expiresAt` is one of the timestamps the service sends in
    // its default number form, like Prepare's `expiresAt`, so the epoch form
    // is accepted here.
    expiresAt: requiredDateTime(payload, 'expiresAt'),
    ownerGrant,
  }
}
