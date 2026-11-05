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

// The body of a signed transfer create.
//
// Shaped from the Owner-authorization registry rather than the OpenAPI, for the
// reason `CreateAccountRequest` sets out: the registry is what DAA
// validates the signed bytes against, so it decides what may be sent.
//
// These are **request** legs and are deliberately not the response legs in
// `models/Transfer.ts`. The two taxonomies differ, and reusing one for the
// other would be wrong in both directions: a request destination is
// `account` or `verified_blockchain`, while a decoded transfer's destination is
// `account` or `blockchain` (the service folds `verified_blockchain` into
// `blockchain` on the way out, since the public read taxonomy has no verified
// form). A request leg also carries no address, chain, or tag — it names a
// destination, it does not describe one — so nothing here needs the redaction
// the response legs are built around.

/**
 * The account a transfer draws from.
 *
 * The registry admits only an account source. Omitted, DAA resolves the
 * effective source itself and still requires its Owner to match the registered
 * credential, so leaving it out is not a way to move someone else's funds.
 */
export type CreateTransferSource = Readonly<{
  type: 'account'
  /** Public account id. Account ids are strings, including numeric ones. */
  id: string
}>

/**
 * Where a transfer sends funds: another DAA account, or a verified blockchain
 * address already registered with DAA.
 *
 * A `oneOf` in the registry, so exactly one arm must match — the two carry
 * disjoint required properties (`id` against `addressId`) and neither admits
 * additional ones, which is what makes "exactly one" decidable.
 */
export type CreateTransferDestination =
  | Readonly<{
      type: 'account'
      /** Public account id. Account ids are strings, including numeric ones. */
      id: string
    }>
  | Readonly<{
      type: 'verified_blockchain'
      /** The registered address's id, which the registry types as a UUID. */
      addressId: string
    }>

/**
 * The amount to transfer.
 *
 * `amount` is a decimal **string**, not a number, for the reason `Money`
 * documents on the way in: JavaScript has one number type and it is an
 * IEEE-754 double, so a large or long amount written as a numeric literal is
 * rounded by `JSON.stringify` before anything can see it — and these are the
 * exact bytes that get signed, so the rounded value is what the Owner would be
 * authorizing. The registry's `decimal` type accepts a JSON string or a JSON
 * number, so the string form is not a workaround.
 */
export type CreateTransferAmount = Readonly<{
  /** Exact decimal literal, e.g. `"10.25"`. */
  amount: string
  /** ISO 4217 code. Not a closed set here — see `Money`. */
  currency: string
}>

/** Optional caller-supplied risk context. The registry requires none of it. */
export type CreateTransferRiskSignals = Readonly<{
  ipAddress?: string
  sessionId?: string
  deviceId?: string
}>

/**
 * Body for creating a transfer.
 *
 * Every field is checked before the body is serialized, and the serialized
 * bytes are the ones signed and sent. An unrecognized property is rejected
 * rather than dropped, at every level of the body — the registry schema
 * refuses additional properties on the request and on each of its nested
 * objects.
 */
export type CreateTransferRequest = Readonly<{
  /**
   * Identifies this transfer attempt. Persist it before sending and never reuse
   * it with different body bytes — the authorization JWS carries this same
   * value as its `idempotency_key` claim.
   */
  idempotencyKey: string
  /** Omitted lets DAA resolve the source; see {@link CreateTransferSource}. */
  source?: CreateTransferSource
  destination: CreateTransferDestination
  amount: CreateTransferAmount
  riskSignals?: CreateTransferRiskSignals
}>
