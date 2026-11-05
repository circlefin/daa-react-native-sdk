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
  REGISTRATION_CODE_CHALLENGE_METHOD,
  newRegistrationCodeVerifier,
  registrationCodeChallengeS256,
} from '../auth/registrationCodeVerifier'
import { fromBase64Url, toBase64Url } from '../crypto/base64url'
import { sha256 } from '../crypto/sha256'

/**
 * The registration handoff's secret half.
 *
 * The construction is RFC 7636's, so its published test vector is the strongest
 * available check that the digest is taken over the right bytes — a challenge
 * derived from the raw random bytes instead of the verifier *string* would look
 * perfectly well-formed and would never match server-side.
 */

// RFC 7636 Appendix B.
const RFC7636_VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
const RFC7636_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'

const BASE64URL_43 = /^[A-Za-z0-9_-]{43}$/

describe('registrationCodeChallengeS256', () => {
  it('matches the RFC 7636 Appendix B vector', () => {
    expect(registrationCodeChallengeS256(RFC7636_VERIFIER)).toBe(RFC7636_CHALLENGE)
  })

  it('is the digest of the verifier string, not of the bytes it was encoded from', () => {
    const verifier = newRegistrationCodeVerifier()
    // Hashing the 32 random bytes the verifier was encoded from is the plausible
    // wrong implementation: same length, same charset, and the server would
    // reject every completion. Pinned explicitly rather than left to the RFC
    // vector above, which only covers a verifier the SDK did not generate.
    const overRawBytes = toBase64Url(sha256(fromBase64Url(verifier)))
    expect(registrationCodeChallengeS256(verifier)).not.toBe(overRawBytes)
  })

  it('always produces the 43-character unpadded Base64URL the contract pins', () => {
    for (let i = 0; i < 16; i++) {
      expect(registrationCodeChallengeS256(newRegistrationCodeVerifier())).toMatch(BASE64URL_43)
    }
  })

  it('is deterministic for one verifier', () => {
    const verifier = newRegistrationCodeVerifier()
    expect(registrationCodeChallengeS256(verifier)).toBe(registrationCodeChallengeS256(verifier))
  })
})

describe('newRegistrationCodeVerifier', () => {
  it('carries 256 bits of entropy in the contract charset', () => {
    const verifier = newRegistrationCodeVerifier()
    expect(verifier).toMatch(BASE64URL_43)
    // minLength: 43 on CompleteDeviceRegistrationRequest.registrationCodeVerifier.
    expect(verifier.length).toBeGreaterThanOrEqual(43)
    expect(fromBase64Url(verifier)).toHaveLength(32)
  })

  it('is fresh per attempt', () => {
    const verifiers = new Set<string>()
    for (let i = 0; i < 64; i++) {
      verifiers.add(newRegistrationCodeVerifier())
    }
    expect(verifiers.size).toBe(64)
  })
})

describe('the challenge method', () => {
  it('is the only value the contract enum allows', () => {
    expect(REGISTRATION_CODE_CHALLENGE_METHOD).toBe('S256')
  })
})
