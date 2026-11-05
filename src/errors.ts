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

// Stable SDK error model. Unknown DAA codes remain observable as
// `api` and are never guessed retryable. Errors never expose Owner grants, JWS
// values, raw key material, native key handles, or sealed server state.
//
// `device_revoked` and `owner_binding_invalid` are reserved: DAA returns no
// code that produces them, so the SDK never throws them. They stay in the type
// so that a later DAA code does not change the public type.

export type DaaSdkError =
  | { kind: 'transport'; retryable: boolean; idempotencyKey?: string }
  | { kind: 'api'; httpStatus: number; daaStatusCode?: string | number; retryable: boolean }
  | { kind: 'local_user_authentication_required' }
  | { kind: 'login_request_expired' }
  | { kind: 'owner_grant_invalid' }
  | { kind: 'owner_grant_expired' }
  | { kind: 'prepare_receipt_invalid' }
  | { kind: 'owner_binding_invalid' }
  | { kind: 'device_not_initialized' }
  | { kind: 'device_revoked' }
  | { kind: 'idempotency_conflict'; idempotencyKey: string; correlationId?: string }
  | { kind: 'contract_violation'; correlationId?: string }

/**
 * An Error carrying a structured `DaaSdkError`. The SDK throws this so callers
 * get the stable model (`err.detail.kind`) instead of raw platform text.
 */
export class DaaError extends Error {
  readonly detail: DaaSdkError
  // The originating error. Kept off `message` (so it never lands in logs by
  // default) but available to a host that deliberately inspects `err.cause`.
  readonly cause: unknown

  constructor(detail: DaaSdkError, message: string, cause: unknown = undefined) {
    super(message)
    this.name = 'DaaError'
    this.detail = detail
    this.cause = cause
    // Keep `cause` non-enumerable so JSON.stringify and crash reporters that
    // walk own enumerable properties do not export the raw native error (its
    // code / userInfo / native stack). It stays readable via `err.cause`.
    Object.defineProperty(this, 'cause', { enumerable: false })
  }
}

/** Narrow an unknown caught value to `DaaError` (so callers can read `.detail`). */
export function isDaaError(err: unknown): err is DaaError {
  return err instanceof DaaError
}

/** A local boundary/contract check failed (no request was sent). */
export function contractViolation(message: string, correlationId?: string | null): DaaError {
  if (correlationId === undefined || correlationId === null) {
    return new DaaError({ kind: 'contract_violation' }, `DAA: ${message}`)
  }
  return new DaaError(
    { kind: 'contract_violation', correlationId },
    `DAA: ${message}${requestIdSuffix(correlationId)}`,
  )
}

/**
 * A correlation id is a server-supplied header value, and it reaches
 * `DaaError.message` — which a consuming app is likely to log verbatim. A header
 * carrying CR, LF, or other control characters could therefore forge log lines,
 * so only printable ASCII is interpolated.
 *
 * This does not cost the value: a correlation id is printable, so the message
 * carries the exact header. Only one already carrying control characters comes
 * through altered, and the missing characters are the ones that made it unsafe.
 * Where the error model carries the field — `contract_violation` — the detail
 * still holds it exactly, for a caller reading it deliberately rather than
 * logging it.
 */
function messageSafe(correlationId: string): string {
  return correlationId.replace(/[^\x20-\x7e]/g, '')
}

/** The ` (requestId=…)` message suffix, or nothing when there is no correlation id. */
function requestIdSuffix(correlationId: string | null): string {
  return correlationId === null ? '' : ` (requestId=${messageSafe(correlationId)})`
}

/**
 * A successful response could not be read as the contract's shape.
 *
 * The same `contract_violation` kind as a local check: the model describes a
 * broken contract, not which side broke it, and a caller's recovery is the same
 * either way — the call cannot be made to succeed by retrying it. What
 * distinguishes this one is `correlationId`, the provider's `X-Request-Id`, which
 * is what makes it diagnosable server-side.
 *
 * Nothing derived from the response *body* is carried. The body is the thing the
 * SDK could not vouch for; a misrouted or intercepted response must not be able
 * to put its own text into a consumer's logs. Not even the name of the field that
 * was missing goes in.
 */
export function malformedResponse(correlationId: string | null): DaaError {
  const detail: DaaSdkError =
    correlationId === null
      ? { kind: 'contract_violation' }
      : { kind: 'contract_violation', correlationId }
  return new DaaError(
    detail,
    `DAA: the response did not match the DAA API contract${requestIdSuffix(correlationId)}`,
  )
}

/**
 * A DAA API call returned an unexpected status.
 *
 * `retryable` is decided by the HTTP status alone. A caller may safely retry
 * `429` and `5xx` responses; write retries must reuse the original body and
 * idempotency key. Other `4xx` responses will not become successes on a second
 * attempt. The DAA status code is carried for logging and support but is
 * deliberately **not** consulted — an unknown DAA code stays observable and is
 * never guessed retryable.
 *
 * `correlationId` goes in the message and **not** on the detail, because the
 * `api` variant does not model one — the error model puts the field on
 * `contract_violation` only, and the SDK does not widen the `api` type to carry
 * it. Sanitising costs nothing here: a correlation id is printable, so the
 * message copy is the exact header. Only a header already carrying control
 * characters differs, and that value is not one to hand back untouched.
 */
export function apiFailure(args: {
  httpStatus: number
  daaStatusCode: string | number | null
  correlationId: string | null
}): DaaError {
  const retryable = args.httpStatus === 429 || args.httpStatus >= 500
  const detail: DaaSdkError = {
    kind: 'api',
    httpStatus: args.httpStatus,
    retryable,
    ...(args.daaStatusCode === null ? {} : { daaStatusCode: args.daaStatusCode }),
  }
  return new DaaError(
    detail,
    `DAA: API call failed (status=${args.httpStatus})${requestIdSuffix(args.correlationId)}`,
  )
}

/**
 * The consumer's transport threw instead of returning a response.
 *
 * The error model calls this `transport`. A throw from `DaaTransport.send` does
 * not say whether the request reached DAA. Cancellation after transport
 * submission remains an ambiguous result and follows the retry rules; a throw
 * from the transport leaves the same unknown outcome. The retry rule is to
 * retry with the same body bytes and the same idempotency key. That is why
 * `retryable` is `true`, and why the idempotency key of the request handed to
 * the transport, when its body has one, goes on the detail: it is the key the
 * retry must reuse.
 *
 * The thrown value is the consumer's own error. It is kept as `cause`, not
 * copied into `message`: the SDK cannot vouch for its text, and `message` is
 * what crash reporters log by default.
 *
 * Every `DaaUserClient` operation reports a transport throw this way. The three
 * login calls (Prepare, Social Session, and Device Registration Complete) do
 * not: they rethrow the consumer's error unchanged, because the SDK mints their
 * idempotency keys itself and does not let a caller resend the same bytes, so
 * `retryable: true` would not be true for them.
 */
export function transportFailure(cause: unknown, idempotencyKey?: string): DaaError {
  const detail: DaaSdkError =
    idempotencyKey === undefined
      ? { kind: 'transport', retryable: true }
      : { kind: 'transport', retryable: true, idempotencyKey }
  return new DaaError(detail, 'DAA: the transport failed before a response was received', cause)
}

/**
 * The pending login request expired (`410`).
 *
 * The contract's rule for the Prepare and Social Session calls: "An exact retry
 * after expiry returns `410`; the SDK starts a new logical attempt with a fresh,
 * permanently unused key." So the caller's recovery is a new `prepareSocialLogin`,
 * not a retry, and the expired key is never reused.
 *
 * `correlationId`, the response's `X-Request-Id`, goes in the message only, as
 * on `api`. The error model puts a correlation id on `contract_violation`;
 * `idempotency_conflict` also carries it, as an optional field (see
 * {@link idempotencyConflict}), and this variant does not.
 */
export function loginRequestExpired(correlationId: string | null): DaaError {
  return new DaaError(
    { kind: 'login_request_expired' },
    `DAA: the login request has expired${requestIdSuffix(correlationId)}`,
  )
}

/**
 * The Prepare receipt could not be verified: it is missing where one is
 * required, malformed, signed by no pinned key, bound to values other than this
 * attempt's, outside its validity window, or the platform verifier is missing
 * or failed.
 *
 * On the login path this is raised only when a trust anchor is pinned for the
 * environment: the SDK then verifies the receipt and fails closed on any
 * mismatch, and nothing from that Prepare response reaches the application.
 * With no anchor pinned, the receipt is ignored. Not retryable in place: the
 * caller's recovery is a new `prepareSocialLogin`, which sends a fresh
 * challenge and flow key. A failure that persists across fresh attempts points
 * at the relay or at trust material that does not match the service's signer,
 * not at the user.
 *
 * The receipt is unverified server-supplied text and never goes into the
 * message; `message` here is one of the SDK's own literals.
 */
export function prepareReceiptInvalid(message: string, cause: unknown = undefined): DaaError {
  return new DaaError({ kind: 'prepare_receipt_invalid' }, `DAA: ${message}`, cause)
}

/**
 * The same error with the response's `X-Request-Id` named in its message.
 *
 * For a check that runs on a decoded response without seeing the response
 * itself — the Prepare receipt's verification has many throw sites and none of
 * them holds the headers — so the caller that does hold the response adds the
 * id once. The detail, the cause, and the stack of the check that threw are
 * unchanged.
 */
export function withRequestId(err: DaaError, correlationId: string | null): DaaError {
  if (correlationId === null) {
    return err
  }
  const correlated = new DaaError(
    err.detail,
    `${err.message}${requestIdSuffix(correlationId)}`,
    err.cause,
  )
  if (err.stack !== undefined) {
    // Keep the frame that names which receipt check failed, with the new message.
    // A function replacer, so a `$` in the server's id is not a replace pattern.
    correlated.stack = err.stack.replace(err.message, () => correlated.message)
  }
  return correlated
}

/**
 * An idempotency key was reused with different request bytes: a `409` with
 * `IDEMPOTENCY_KEY_REUSED` (`420034`). Another `409` is not this error.
 *
 * The key goes on the detail so a caller can correlate the conflict; it stays
 * out of `message` because that string is what crash reporters log by default.
 * The response's `X-Request-Id` is the server's id, not the caller's, so it goes
 * in both, in the shape `contract_violation` uses: a host that reports
 * `err.detail` rather than the message can still trace the conflict
 * server-side. The error model puts a correlation id on `contract_violation`;
 * `idempotency_conflict` also carries it, as an optional field.
 */
export function idempotencyConflict(
  idempotencyKey: string,
  correlationId: string | null,
): DaaError {
  const detail: DaaSdkError =
    correlationId === null
      ? { kind: 'idempotency_conflict', idempotencyKey }
      : { kind: 'idempotency_conflict', idempotencyKey, correlationId }
  return new DaaError(
    detail,
    `DAA: idempotency key was reused with a different request${requestIdSuffix(correlationId)}`,
  )
}

/**
 * Map an error thrown by the native secure-key module onto `DaaSdkError`. The
 * raw native message is never propagated into `.message` — it can contain
 * keystore/enclave internals that must not reach host-app logs — but is retained
 * as `.cause` for deliberate inspection.
 *
 * An already-structured `DaaError` passes through unchanged. Otherwise a stable
 * `code` on the native error maps the known custody states; anything else
 * collapses to `contract_violation`.
 */
export function mapNativeError(err: unknown): DaaError {
  if (err instanceof DaaError) {
    return err
  }
  const code = (err as { code?: unknown } | null | undefined)?.code
  if (code === 'USER_AUTH_REQUIRED') {
    return new DaaError(
      { kind: 'local_user_authentication_required' },
      'DAA: user authentication is required',
      err,
    )
  }
  if (code === 'NOT_INITIALIZED') {
    return new DaaError(
      { kind: 'device_not_initialized' },
      'DAA: secure key is not initialized',
      err,
    )
  }
  return new DaaError(
    { kind: 'contract_violation' },
    'DAA: native secure-key operation failed',
    err,
  )
}
