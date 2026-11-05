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

// The DAA-signed Prepare receipt.
//
// When a trust anchor is pinned for the environment, the SDK verifies the
// returned Prepare receipt before starting provider login and fails closed if
// the receipt is missing or does not verify. With no anchor pinned, the SDK
// ignores the receipt (see below).
//
// **What it defends against.** The SDK reaches DAA through the application's
// own backend, which the trust model treats as untrusted. Without a verified
// receipt that relay can substitute a different login request — another
// attempt's `loginRequestId` and nonce — and the SDK would hand that nonce to
// provider login. The receipt is DAA-signed, so the relay cannot mint one for
// substituted values. What makes the signature an answer is binding its claims
// to values the relay cannot choose: the registration code challenge and the
// registration-flow key thumbprint the SDK generated itself, before Prepare
// was sent. Those two are the load-bearing checks. Tenant scope alone would not
// be: two attempts under one customer app carry identical tenant claims.
//
// **Claims.** The claim set DAA signs under `typ: daa-prepare-receipt+jws`:
// `iss`, `aud`, `iat`, `exp`, `jti`, `environment`, `customerAppId`,
// `parentEntityIdDigest`, `provider`, `loginRequestId`, `nonce`,
// `registrationCodeChallenge`, `registrationFlowKeyThumbprint`. The
// `nonce` claim carries the value the Prepare response calls `oidcNonce`.
// There is no state claim: `oidcState` is not bound by the receipt.
//
// **Tenant scope is not checked on the login path.** Comparing
// `customerAppId` / `parentEntityIdDigest` needs the parent entity the SDK
// expects, and the SDK defines no mapping from `DaaSdkConfiguration.appId` to
// DAA's parent entity. {@link requirePrepareReceiptTenantScope} is the
// comparison; the login path does not call it.
//
// **No trust anchor is pinned in this release.** The anchor (issuer, audience,
// signing keys, clock allowance) ships inside the SDK build, and
// {@link pinnedPrepareReceiptTrustAnchor} returns `null` for every environment.
// {@link checkPrepareReceipt} defines what login does in each case: with no
// anchor, the SDK ignores a receipt rather than failing on it. Ignoring loses
// nothing, because an SDK with no anchor could not verify the receipt anyway.
// It does mean `oidcNonce` and `oidcState` are not authenticated by the SDK:
// integrators bind the provider redirect with their own OAuth `state`.
//
// **Errors.** Every failure to verify a receipt the SDK needs is
// `prepare_receipt_invalid`. Faults in the SDK's own inputs — a
// malformed pinned anchor, an incomplete expectation, a bad test clock, a
// parent entity id that is not a canonical UUID — are `contract_violation`,
// because they describe this build, not the receipt.

import type { DaaEnvironment } from '../config'
import { fromBase64Url, toBase64Url } from '../crypto/base64url'
import { ownMember, verifyCompactEs256, type PinnedEs256Key } from '../crypto/es256Jws'
import type { P256PublicJwk } from '../crypto/jwkThumbprint'
import { sha256 } from '../crypto/sha256'
import { contractViolation, DaaError, isDaaError, prepareReceiptInvalid } from '../errors'
import { isUuid } from '../validation/uuid'

/** Contract bounds on `SocialLoginRequest.prepareReceiptJws`. */
export const PREPARE_RECEIPT_MIN_LENGTH = 64
export const PREPARE_RECEIPT_MAX_LENGTH = 8192

/** The JWS `typ` DAA signs the receipt with. */
export const PREPARE_RECEIPT_TYP = 'daa-prepare-receipt+jws'

/** Widest clock skew an anchor may allow, so a configuration typo cannot disable expiry. */
export const PREPARE_RECEIPT_MAX_CLOCK_SKEW_SECONDS = 300

/** Compact JWS serialization: three Base64URL segments separated by dots. */
const COMPACT_JWS = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/

/** One pinned receipt-signing key, addressed by the `kid` DAA puts in the header. */
export type PrepareReceiptVerificationKey = Readonly<{ kid: string; jwk: P256PublicJwk }>

/**
 * Everything a trust anchor pins, in one value.
 *
 * `verificationKeys` is pinned by the build and never derived from a receipt.
 * More than one entry allows a rotation overlap; the receipt's `kid` selects
 * among them and nothing else.
 */
export type PrepareReceiptTrustAnchor = Readonly<{
  /** Exact expected `iss`. */
  issuer: string
  /** Exact expected `aud`, or one member of an `aud` array. */
  audience: string
  verificationKeys: readonly PrepareReceiptVerificationKey[]
  /** Allowance on `exp` / `iat` / `nbf`, in seconds. */
  maxClockSkewSeconds: number
}>

/**
 * The build-time pinned anchor for an environment. **`null` for every
 * environment in this release.**
 *
 * A function rather than a `const`, so that its declared return type does not
 * narrow the rest of this module to unreachable code.
 */
export function pinnedPrepareReceiptTrustAnchor(
  environment: DaaEnvironment,
): PrepareReceiptTrustAnchor | null {
  void environment
  return null
}

/**
 * The values this attempt's receipt must name. The first two come from the
 * Prepare response; the rest are the SDK's own.
 */
export type PrepareReceiptExpectation = Readonly<{
  loginRequestId: string
  /** The Prepare response's `oidcNonce`; the receipt's `nonce` claim. */
  nonce: string
  provider: string
  environment: DaaEnvironment
  registrationCodeChallenge: string
  registrationFlowKeyThumbprint: string
}>

/**
 * Test-only clock, following `auth/deviceAuthorization.ts`: production code
 * always uses the system clock, and no production caller passes one.
 */
export type PrepareReceiptClock = Readonly<{ nowEpochSeconds: () => number }>

const SYSTEM_CLOCK: PrepareReceiptClock = {
  nowEpochSeconds: () => Math.floor(Date.now() / 1000),
}

/** What a verified receipt attested. Only ever returned after every check passed. */
export type VerifiedPrepareReceipt = Readonly<{
  /** The receipt exactly as received. */
  compactJws: string
  loginRequestId: string
  nonce: string
  expiresAtEpochSeconds: number
  /** Signed but not compared on the login path; see {@link requirePrepareReceiptTenantScope}. */
  tenantScope: Readonly<{ customerAppId: unknown; parentEntityIdDigest: unknown }>
}>

/**
 * Whether a value is shaped like the compact JWS the contract describes and sits
 * within its declared length bounds. Structural only: shape is not trust.
 */
export function isPrepareReceiptShape(value: string): boolean {
  return (
    value.length >= PREPARE_RECEIPT_MIN_LENGTH &&
    value.length <= PREPARE_RECEIPT_MAX_LENGTH &&
    COMPACT_JWS.test(value)
  )
}

/**
 * What login does with the receipt, given the anchor for this environment.
 *
 * | Anchor | Receipt | Result                                                      |
 * | ------ | ------- | ----------------------------------------------------------- |
 * | unset  | absent  | `null`: nothing to verify, login proceeds                   |
 * | unset  | present | `null`: the receipt is ignored, login proceeds as if absent |
 * | set    | absent  | `prepare_receipt_invalid`: the receipt is required          |
 * | set    | present | {@link verifyPrepareReceipt}; any failure throws            |
 *
 * `prepareReceiptJws` is the raw response member: `undefined` or `null` is
 * absent, and anything else is present, whatever its type. In the first two
 * rows it is not read at all, and `expected` is a thunk so they compute
 * nothing: with no anchor, the login path does no receipt work.
 *
 * In the second row, an SDK without the anchor ignores the receipt: it could
 * not verify it, so ignoring gives up no protection. An ignored receipt is
 * never passed on as if it were checked: this returns `null` for it exactly as
 * for no receipt, so the login path hands the application no receipt at all.
 */
export async function checkPrepareReceipt(
  prepareReceiptJws: unknown,
  anchor: PrepareReceiptTrustAnchor | null,
  expected: () => PrepareReceiptExpectation,
  clock: PrepareReceiptClock = SYSTEM_CLOCK,
): Promise<VerifiedPrepareReceipt | null> {
  if (anchor === null) {
    return null
  }
  if (prepareReceiptJws === undefined || prepareReceiptJws === null) {
    throw prepareReceiptInvalid(
      'the Prepare response carries no receipt, and this environment requires one',
    )
  }
  return verifyPrepareReceipt(prepareReceiptJws, anchor, expected(), clock)
}

/**
 * Verify the receipt against a trust anchor and this attempt's expectation.
 *
 * Order: the anchor and the expectation first, because a fault in either is a
 * configuration error; then the receipt's shape; then its header and signature;
 * and only then the claims, because a claim from an unverified token is not
 * evidence of anything.
 *
 * A fault in the anchor, the expectation, or the clock is `contract_violation`;
 * every rejection of the receipt itself, including a platform verifier that is
 * missing or fails, is `prepare_receipt_invalid`.
 *
 * The receipt is never interpolated into an error: it is unverified
 * server-supplied text, and a consumer is likely to log the message verbatim.
 */
export async function verifyPrepareReceipt(
  prepareReceiptJws: unknown,
  anchor: PrepareReceiptTrustAnchor,
  expected: PrepareReceiptExpectation,
  clock: PrepareReceiptClock = SYSTEM_CLOCK,
): Promise<VerifiedPrepareReceipt> {
  const keys = pinnedKeys(anchor)
  requireExpectation(expected)
  const now = clock.nowEpochSeconds()
  if (!Number.isInteger(now) || now <= 0) {
    throw contractViolation('the Prepare receipt clock must yield a positive Unix timestamp')
  }

  if (typeof prepareReceiptJws !== 'string' || !isPrepareReceiptShape(prepareReceiptJws)) {
    throw prepareReceiptInvalid(
      'the Prepare receipt is not a compact JWS within the contract length bounds',
    )
  }

  const result = await platformVerify(prepareReceiptJws, keys)
  if (!result.verified) {
    throw prepareReceiptInvalid(`the Prepare receipt did not verify (${result.reason})`)
  }

  const claims = result.payload
  requireClaimEquals(claims, 'iss', anchor.issuer)
  requireAudience(claims, anchor.audience)
  requireNonEmptyClaim(claims, 'jti')
  requireClaimEquals(claims, 'environment', expected.environment)
  requireClaimEquals(claims, 'provider', expected.provider)
  requireClaimEquals(claims, 'loginRequestId', expected.loginRequestId)
  requireClaimEquals(claims, 'nonce', expected.nonce)
  requireClaimEquals(claims, 'registrationCodeChallenge', expected.registrationCodeChallenge)
  requireClaimEquals(
    claims,
    'registrationFlowKeyThumbprint',
    expected.registrationFlowKeyThumbprint,
  )
  const expiresAtEpochSeconds = requireTimeClaims(claims, now, anchor.maxClockSkewSeconds)

  return {
    compactJws: prepareReceiptJws,
    loginRequestId: expected.loginRequestId,
    nonce: expected.nonce,
    expiresAtEpochSeconds,
    tenantScope: {
      customerAppId: ownMember(claims, 'customerAppId'),
      parentEntityIdDigest: ownMember(claims, 'parentEntityIdDigest'),
    },
  }
}

/**
 * The signature check, with a platform verifier that is missing or fails
 * reported as the receipt failing to verify.
 *
 * `pinnedKeys` has already validated everything {@link verifyCompactEs256}
 * would reject as a configuration error, so the only `DaaError` left to come
 * out of it is the platform's: no `DaaRegistration` module, one without the
 * verify function, or a native rejection. A native rejection also covers a
 * pinned point the platform does not accept as on the curve — the one anchor
 * fault only the platform can see, and indistinguishable here from the rest.
 * The SDK's own message and the original error (as `cause`) are kept.
 */
async function platformVerify(
  jws: string,
  keys: readonly PinnedEs256Key[],
): Promise<Awaited<ReturnType<typeof verifyCompactEs256>>> {
  try {
    return await verifyCompactEs256(jws, { keys, expectedTyp: PREPARE_RECEIPT_TYP })
  } catch (err) {
    if (isDaaError(err) && err.detail.kind === 'contract_violation') {
      throw new DaaError({ kind: 'prepare_receipt_invalid' }, err.message, err)
    }
    throw err
  }
}

/**
 * Domain separator for `parentEntityIdDigest`, byte-for-byte the one DAA
 * signs with. The trailing NUL is part of it.
 */
export const PARENT_ENTITY_ID_DIGEST_DOMAIN = 'daa-prepare-receipt-parent-entity-digest-v1\0'

/**
 * `base64url_nopad(SHA-256(utf8(domain) || utf8(parentEntityId)))`, where the
 * id is the canonical lower-case hyphenated UUID — DAA's pinned formula.
 */
export function parentEntityIdDigest(parentEntityId: string): string {
  if (
    typeof parentEntityId !== 'string' ||
    !isUuid(parentEntityId) ||
    parentEntityId !== parentEntityId.toLowerCase()
  ) {
    throw contractViolation('parentEntityId must be a canonical lower-case UUID')
  }
  const encoder = new TextEncoder()
  const domain = encoder.encode(PARENT_ENTITY_ID_DIGEST_DOMAIN)
  const id = encoder.encode(parentEntityId)
  const input = new Uint8Array(domain.length + id.length)
  input.set(domain)
  input.set(id, domain.length)
  return toBase64Url(sha256(input))
}

/**
 * Tenant-scope comparison for a verified receipt. **Not called on the login
 * path:** the SDK has no defined way to derive the expected parent entity from
 * its configuration. A caller that has the expected values calls this after
 * {@link verifyPrepareReceipt}.
 */
export function requirePrepareReceiptTenantScope(
  receipt: VerifiedPrepareReceipt,
  expected: Readonly<{ customerAppId: string; parentEntityId: string }>,
): void {
  const { customerAppId, parentEntityIdDigest: digest } = receipt.tenantScope
  if (typeof customerAppId !== 'string' || customerAppId !== expected.customerAppId) {
    throw prepareReceiptInvalid('the Prepare receipt does not bind the expected customerAppId')
  }
  if (typeof digest !== 'string' || digest !== parentEntityIdDigest(expected.parentEntityId)) {
    throw prepareReceiptInvalid(
      'the Prepare receipt does not bind the expected parentEntityIdDigest',
    )
  }
}

/**
 * Validate the anchor and convert its keys to the points the platform verifies
 * against. A malformed anchor is a configuration error, not a rejected receipt.
 * Whether each point is on the curve is the platform's check.
 */
function pinnedKeys(anchor: PrepareReceiptTrustAnchor): readonly PinnedEs256Key[] {
  if (typeof anchor !== 'object' || anchor === null) {
    throw contractViolation('the Prepare receipt trust anchor must be an object')
  }
  if (typeof anchor.issuer !== 'string' || anchor.issuer.length === 0) {
    throw contractViolation('the Prepare receipt trust anchor must name an issuer')
  }
  if (typeof anchor.audience !== 'string' || anchor.audience.length === 0) {
    throw contractViolation('the Prepare receipt trust anchor must name an audience')
  }
  if (
    !Number.isInteger(anchor.maxClockSkewSeconds) ||
    anchor.maxClockSkewSeconds < 0 ||
    anchor.maxClockSkewSeconds > PREPARE_RECEIPT_MAX_CLOCK_SKEW_SECONDS
  ) {
    throw contractViolation(
      'the Prepare receipt trust anchor clock skew must be between 0 and ' +
        `${PREPARE_RECEIPT_MAX_CLOCK_SKEW_SECONDS} seconds`,
    )
  }
  if (!Array.isArray(anchor.verificationKeys) || anchor.verificationKeys.length === 0) {
    throw contractViolation('the Prepare receipt trust anchor must pin at least one P-256 key')
  }
  const kids = new Set<string>()
  for (const key of anchor.verificationKeys) {
    if (typeof key !== 'object' || key === null) {
      throw contractViolation('every Prepare receipt verification key must be an object')
    }
    if (typeof key.kid !== 'string' || key.kid.length === 0) {
      throw contractViolation('every Prepare receipt verification key must have a non-empty kid')
    }
    if (kids.has(key.kid)) {
      throw contractViolation('Prepare receipt verification keys must have distinct kids')
    }
    kids.add(key.kid)
  }
  return anchor.verificationKeys.map((key) => ({
    kid: key.kid,
    publicKeyX963: x963FromJwk(key.jwk),
  }))
}

function x963FromJwk(jwk: P256PublicJwk): Uint8Array {
  if (typeof jwk !== 'object' || jwk === null || jwk.kty !== 'EC' || jwk.crv !== 'P-256') {
    throw contractViolation('a Prepare receipt verification key must be an EC P-256 JWK')
  }
  let x: Uint8Array
  let y: Uint8Array
  try {
    x = fromBase64Url(jwk.x)
    y = fromBase64Url(jwk.y)
  } catch {
    throw contractViolation('a Prepare receipt verification key has a non-Base64URL coordinate')
  }
  if (x.length !== 32 || y.length !== 32) {
    throw contractViolation(
      'a Prepare receipt verification key must have 32-byte x and y coordinates',
    )
  }
  const point = new Uint8Array(65)
  point[0] = 0x04
  point.set(x, 1)
  point.set(y, 33)
  return point
}

function requireExpectation(expected: PrepareReceiptExpectation): void {
  if (typeof expected !== 'object' || expected === null) {
    throw contractViolation(
      'verifying a Prepare receipt requires the expected values for this attempt',
    )
  }
  for (const name of [
    'loginRequestId',
    'nonce',
    'provider',
    'environment',
    'registrationCodeChallenge',
    'registrationFlowKeyThumbprint',
  ] as const) {
    const value = expected[name]
    if (typeof value !== 'string' || value.length === 0) {
      throw contractViolation(`verifying a Prepare receipt requires the expected ${name}`)
    }
  }
}

/**
 * Exact string equality on one claim. Not constant-time, and does not need to
 * be: every value compared is one the SDK sent, generated, or relayed to the
 * application; none is a secret. The claim name goes in the message — it is
 * one of this module's literals — and the value never does.
 */
function requireClaimEquals(
  claims: Readonly<Record<string, unknown>>,
  name: string,
  expected: string,
): void {
  const actual = ownMember(claims, name)
  if (typeof actual !== 'string' || actual !== expected) {
    throw prepareReceiptInvalid(`the Prepare receipt does not bind the expected ${name}`)
  }
}

function requireNonEmptyClaim(claims: Readonly<Record<string, unknown>>, name: string): void {
  const actual = ownMember(claims, name)
  if (typeof actual !== 'string' || actual.length === 0) {
    throw prepareReceiptInvalid(`the Prepare receipt does not carry a ${name}`)
  }
}

/** RFC 7519 §4.1.3: `aud` is a string or an array of strings that must contain ours. */
function requireAudience(claims: Readonly<Record<string, unknown>>, audience: string): void {
  const actual = ownMember(claims, 'aud')
  if (typeof actual === 'string' && actual === audience) {
    return
  }
  if (Array.isArray(actual) && actual.some((value) => value === audience)) {
    return
  }
  throw prepareReceiptInvalid('the Prepare receipt does not bind the expected aud')
}

/**
 * `exp` and `iat` are required (DAA always sets both); `nbf` is checked when
 * present. All are RFC 7519 NumericDates in seconds — deliberately not the
 * epoch-millis tolerance `wire/instant.ts` carries for the Prepare body, since
 * DAA's signer emits seconds. A millisecond value fails the upper bound below
 * instead of passing as an expiry thousands of years out.
 */
function requireTimeClaims(
  claims: Readonly<Record<string, unknown>>,
  nowEpochSeconds: number,
  maxClockSkewSeconds: number,
): number {
  const exp = requireNumericDate(claims, 'exp')
  const iat = requireNumericDate(claims, 'iat')
  if (exp + maxClockSkewSeconds < nowEpochSeconds) {
    throw prepareReceiptInvalid('the Prepare receipt has expired')
  }
  if (iat - maxClockSkewSeconds > nowEpochSeconds) {
    throw prepareReceiptInvalid('the Prepare receipt is not valid yet (iat is in the future)')
  }
  if (iat > exp) {
    throw prepareReceiptInvalid('the Prepare receipt expires before it was issued')
  }
  if (ownMember(claims, 'nbf') !== undefined) {
    const nbf = requireNumericDate(claims, 'nbf')
    if (nbf - maxClockSkewSeconds > nowEpochSeconds) {
      throw prepareReceiptInvalid('the Prepare receipt is not valid yet (nbf is in the future)')
    }
  }
  return exp
}

/** Past year 9999 is not a clock; it is a unit mistake or a receipt that never expires. */
const MAX_NUMERIC_DATE = 253402300799

function requireNumericDate(claims: Readonly<Record<string, unknown>>, name: string): number {
  const value = ownMember(claims, name)
  if (value === undefined) {
    throw prepareReceiptInvalid(`the Prepare receipt does not carry an ${name}`)
  }
  if (
    typeof value !== 'number' ||
    !Number.isInteger(value) ||
    value <= 0 ||
    value > MAX_NUMERIC_DATE
  ) {
    throw prepareReceiptInvalid(`the Prepare receipt carries a malformed ${name}`)
  }
  return value
}
