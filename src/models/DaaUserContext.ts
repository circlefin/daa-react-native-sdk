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
import { contractViolation } from '../errors'
import type { OwnerAuthKey } from '../securekey/SecureKey'

/** RFC 7638 P-256 JWK thumbprints are 32-byte unpadded Base64URL digests. */
const JWK_THUMBPRINT = /^[A-Za-z0-9_-]{43}$/

/**
 * Owner-bound local SDK context: `DaaUserContext`.
 *
 * Produced only by an `ACTIVE` Device Registration Complete. It is not a DAA
 * bearer token or an application session. The `#` private field makes the type
 * nominal: an object literal cannot be typed or passed as one, so `forUser`
 * cannot be opened with a fabricated context. The constructor is also brand-
 * gated (see `DECODER_TOKEN` below), so holding one real context does not let
 * a caller reach the class through `ctx.constructor` and mint another for a
 * different Owner.
 *
 * Not constructible by a consumer: exported from `index.ts` as a type only.
 */
export type DeviceContext = Readonly<{
  deviceCredentialStatus: 'active'
  ownerBindingId: string
  authKeyId: string
  /**
   * When the context was resolved, as ISO-8601 text. The decoder also accepts
   * the epoch-millisecond form the service sends for this timestamp and
   * normalises it here, so a consumer never sees the wire's disagreement.
   */
  resolvedAt: string
}>

/**
 * Brands the constructor, not just the instance. `isActiveDaaUserContext`'s
 * `instanceof` plus its read of `#active` stops a consumer-fabricated object
 * literal, but not the class itself: any code holding one real
 * `DaaUserContext` can still reach `DaaUserContext` via `ctx.constructor` and
 * call it directly, with no import of this module at all. Requiring this
 * exact `Symbol` as the constructor's first argument closes that path —
 * `ctx.constructor` is reachable, but constructing anything with it throws
 * unless the caller already holds this token, and the only two places that do
 * are the decoder call sites below and in `../wire/deviceRegistrationResultPayload.ts`.
 *
 * Exported so those wire decoders can import it, but never re-exported from
 * `index.ts` — the package's `exports` map has no entry for this module's
 * path, so a consuming application cannot import it either.
 */
export const DECODER_TOKEN: unique symbol = Symbol('daa.context')

/** Internal storage: the binding must not become part of the public context shape. */
const AUTH_KEY_THUMBPRINTS = new WeakMap<DaaUserContext, string>()

export class DaaUserContext {
  readonly clientEntityId: string
  readonly deviceContext: DeviceContext
  readonly #active: true

  /**
   * @internal Constructed only by this module and the Device Registration
   * Complete decoder, which are the only code paths able to supply `token`.
   */
  constructor(
    token: symbol,
    fields: { readonly clientEntityId: string; readonly deviceContext: DeviceContext },
    /** @internal Set only after Complete pairs the response with its local AuthKey. */
    authKeyThumbprint?: string,
  ) {
    if (token !== DECODER_TOKEN) {
      throw contractViolation('DaaUserContext must be constructed by the DAA decoder')
    }
    if (!isUuid(fields.clientEntityId)) {
      throw contractViolation('DaaUserContext.clientEntityId must be a UUID')
    }
    // Re-checked here rather than only trusted from the wire decoder: this
    // constructor is the sole gate the brand above funnels every caller
    // through, so the invariants the decoder happens to also enforce should
    // hold no matter which of its call sites reaches this point.
    if (fields.deviceContext.deviceCredentialStatus !== 'active') {
      throw contractViolation('DaaUserContext.deviceContext.deviceCredentialStatus must be active')
    }
    if (!isUuid(fields.deviceContext.authKeyId)) {
      throw contractViolation('DaaUserContext.deviceContext.authKeyId must be a UUID')
    }
    if (authKeyThumbprint !== undefined && !JWK_THUMBPRINT.test(authKeyThumbprint)) {
      throw contractViolation('DaaUserContext AuthKey thumbprint is malformed')
    }
    this.clientEntityId = fields.clientEntityId
    this.deviceContext = Object.freeze({
      deviceCredentialStatus: fields.deviceContext.deviceCredentialStatus,
      ownerBindingId: fields.deviceContext.ownerBindingId,
      authKeyId: fields.deviceContext.authKeyId,
      resolvedAt: fields.deviceContext.resolvedAt,
    })
    this.#active = true
    if (authKeyThumbprint !== undefined) {
      AUTH_KEY_THUMBPRINTS.set(this, authKeyThumbprint)
    }
    Object.freeze(this)
  }

  /** @internal */
  isActive(): boolean {
    return this.#active
  }
}

/**
 * Pair an ACTIVE server context with the AuthKey that authorized Complete.
 *
 * The server-assigned `authKeyId` remains the JWS `kid`; the thumbprint is a
 * local, non-enumerable guard that prevents a later key resolution from being
 * silently paired with that server identifier. The returned context is a new
 * branded value because contexts are immutable once exposed to an application.
 */
export function bindAuthKeyToContext(
  context: DaaUserContext,
  authKeyThumbprint: string,
): DaaUserContext {
  if (!isActiveDaaUserContext(context)) {
    throw contractViolation('only an ACTIVE DaaUserContext can be bound to an AuthKey')
  }
  return new DaaUserContext(
    DECODER_TOKEN,
    { clientEntityId: context.clientEntityId, deviceContext: context.deviceContext },
    authKeyThumbprint,
  )
}

/** Fail closed when the local key no longer matches the key paired at Complete. */
export async function assertAuthKeyMatchesContext(
  context: DaaUserContext,
  authKey: OwnerAuthKey,
): Promise<void> {
  const expectedThumbprint = AUTH_KEY_THUMBPRINTS.get(context)
  if (expectedThumbprint === undefined) {
    throw contractViolation('DaaUserContext has no local AuthKey binding')
  }
  if ((await authKey.thumbprint()) !== expectedThumbprint) {
    throw contractViolation('the resolved AuthKey does not match the ACTIVE DaaUserContext')
  }
}

/** True only for a context this SDK decoded from an ACTIVE registration. */
export function isActiveDaaUserContext(value: unknown): value is DaaUserContext {
  return value instanceof DaaUserContext && value.isActive()
}

export type DeviceRegistrationResult =
  | Readonly<{ status: 'ACTIVE'; context: DaaUserContext }>
  | Readonly<{
      status: 'RECOVERY_PENDING'
      recoveryReference: string
      expiresAt: string
    }>
