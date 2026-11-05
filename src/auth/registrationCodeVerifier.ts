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

// The PKCE-shaped handoff that binds Prepare to Device Registration Complete.
//
// Before Prepare, the SDK generates and stores a high-entropy registration
// code verifier and an ephemeral P-256 registration-flow key. Prepare sends
// only the S256 challenge and the ephemeral public key, never an AuthKey
// public key.
//
// Two values, two calls:
//
// - the **challenge** (`S256(verifier)`) goes out at Prepare, in
//   `PrepareSocialLoginRequest.registrationCodeChallenge`;
// - the **verifier** itself goes out only at Device Registration Complete, in
//   `CompleteDeviceRegistrationRequest.registrationCodeVerifier`, where DAA
//   re-derives the digest and matches it against the prepared challenge.
//
// The verifier is therefore a secret for the life of one login attempt. It is
// never logged, never put in an error message, and never exposed on a public
// field — `PreparedSocialLogin` holds it behind a `#` private field.
//
// This is PKCE's construction, not PKCE's protocol. No authorization code is
// exchanged anywhere in this flow: the SDK supplies `idToken` directly, and no
// authorization-code exchange, PKCE, token endpoint, or provider client secret
// participates in completion. The verifier binds the SDK instance that
// prepared the attempt to the SDK instance that completes the registration; it
// does not talk to the identity provider at all. The names come from the
// contract's own fields (`registrationCode*`), which is why they read like PKCE.

import { toBase64Url } from '../crypto/base64url'
import { randomBytes } from '../crypto/random'
import { sha256 } from '../crypto/sha256'

/**
 * 32 bytes → 43 unpadded Base64URL characters, which is both the RFC 7636
 * maximum-entropy recommendation and the contract's `minLength: 43` for
 * `registrationCodeVerifier`.
 */
const VERIFIER_ENTROPY_BYTES = 32

/** The one challenge method the contract's enum allows. */
export const REGISTRATION_CODE_CHALLENGE_METHOD = 'S256'

/** Mint a fresh high-entropy registration code verifier for one login attempt. */
export function newRegistrationCodeVerifier(): string {
  return toBase64Url(randomBytes(VERIFIER_ENTROPY_BYTES))
}

/**
 * The S256 challenge for a verifier: unpadded Base64URL of the SHA-256 digest of
 * the verifier's ASCII bytes. Always 43 characters, matching the contract's
 * `^[A-Za-z0-9_-]{43}$`.
 *
 * The digest is taken over the verifier **string**, not over the random bytes it
 * was encoded from. That is what RFC 7636 specifies and what the server can
 * reproduce, since the verifier string is the only form it ever receives.
 */
export function registrationCodeChallengeS256(verifier: string): string {
  return toBase64Url(sha256(new TextEncoder().encode(verifier)))
}
