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

// The body of a signed withdrawal create.
//
// Shaped from the Owner-authorization registry rather than the OpenAPI, for the
// reason `CreateAccountRequest` and `CreateTransferRequest` set out: the
// digest-pinned registry is what DAA validates the signed bytes against, so it
// decides what may be sent.
//
// One place they disagree, worth naming: the public OpenAPI's
// `FiatPayoutToMoney.amount` (`toAmount.amount`) is `readOnly`, describing a
// value the service computes on read. The registry's `toAmount` schema names
// `amount` as an ordinary optional property of the signed request body, with no
// such marker. The registry wins for signed bytes — refusing it locally would
// reject a body DAA accepts, and a service that does not want a
// caller-supplied conversion amount answers on its own terms.

/**
 * The account a withdrawal draws from.
 *
 * The registry admits only an account source. Omitted, DAA resolves the
 * effective source itself and still requires its Owner to match the registered
 * credential, so leaving it out is not a way to move someone else's funds. See
 * `CreateTransferSource`, which this mirrors.
 */
export type CreateWithdrawalSource = Readonly<{
  type: 'account'
  /** Public account id. Account ids are strings, including numeric ones. */
  id: string
}>

/**
 * The bank destination a withdrawal pays out to: a registered wire or ACH fiat
 * account.
 */
export type CreateWithdrawalDestination = Readonly<{
  type: 'wire' | 'ach'
  /** The registered fiat account's id, which the registry types as a UUID. */
  id: string
  /** Caller-supplied label for the destination. */
  name?: string
}>

/**
 * The amount to withdraw.
 *
 * `amount` is a decimal **string**, not a number, for the reason `Money` and
 * `CreateTransferAmount` document: JavaScript has one number type and it is an
 * IEEE-754 double, so a numeric literal is rounded by `JSON.stringify` before
 * anything can see it — and these are the exact bytes that get signed, so the
 * rounded value is what the Owner would be authorizing.
 */
export type CreateWithdrawalAmount = Readonly<{
  /** Exact decimal literal, e.g. `"10.25"`. */
  amount: string
  /** ISO 4217 code. Not a closed set here — see `Money`. */
  currency: string
}>

/**
 * A target fiat amount for a cross-currency payout.
 *
 * The registry requires only `currency`; `amount` is optional and, unlike
 * {@link CreateWithdrawalAmount.amount}, may be omitted to let DAA resolve the
 * converted amount itself.
 */
export type CreateWithdrawalToAmount = Readonly<{
  /** Exact decimal literal. Omitted lets DAA compute the converted amount. */
  amount?: string
  currency: 'USD' | 'EUR'
}>

/** Optional caller-supplied risk context. The registry requires none of it. */
export type CreateWithdrawalRiskSignals = Readonly<{
  ipAddress?: string
  sessionId?: string
  deviceId?: string
}>

/**
 * Body for creating a withdrawal.
 *
 * Every field is checked before the body is serialized, and the serialized
 * bytes are the ones signed and sent. An unrecognized property is rejected
 * rather than dropped, at every level of the body — the registry schema
 * refuses additional properties on the request and on each of its nested
 * objects.
 */
export type CreateWithdrawalRequest = Readonly<{
  /**
   * Identifies this withdrawal attempt. Persist it before sending and never
   * reuse it with different body bytes — the authorization JWS carries this
   * same value as its `idempotency_key` claim.
   */
  idempotencyKey: string
  /** Omitted lets DAA resolve the source; see {@link CreateWithdrawalSource}. */
  source?: CreateWithdrawalSource
  destination: CreateWithdrawalDestination
  amount: CreateWithdrawalAmount
  toAmount?: CreateWithdrawalToAmount
  riskSignals?: CreateWithdrawalRiskSignals
  /** Sweep the full source balance. DAA defaults this to `false` when omitted. */
  burnAll?: boolean
}>
