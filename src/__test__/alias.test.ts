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

import { deriveKeyScope, parseSecureKeyAlias, secureKeyAlias } from '../securekey/alias'

// Any UUID; `isUuid` does not require a version nibble.
const CLIENT_ENTITY_ID = '00000000-0000-4000-8000-000000000001'
const OTHER_CLIENT_ENTITY_ID = '00000000-0000-4000-8000-000000000002'

// A pinned worked example: SHA-256 over the UTF-8 bytes of
// `acme` + NUL + `sandbox` + NUL + `00000000-0000-4000-8000-000000000001`,
// truncated to the first 16 bytes and re-encoded as unpadded Base64URL.
// Recomputing this by hand is the fastest way to confirm `deriveKeyScope`
// hasn't silently changed its preimage or truncation.
const ACME_SANDBOX_OWNER_1_SCOPE = 'lS_9Ek7W1iNw6422KoRTwA'

describe('deriveKeyScope', () => {
  it('matches a pinned worked example', () => {
    expect(
      deriveKeyScope({
        appId: 'acme',
        environment: 'sandbox',
        clientEntityId: CLIENT_ENTITY_ID,
      }),
    ).toBe(ACME_SANDBOX_OWNER_1_SCOPE)
  })

  it('is exactly 22 unpadded-Base64URL characters (128-bit digest)', () => {
    const scope = deriveKeyScope({
      appId: 'acme',
      environment: 'sandbox',
      clientEntityId: CLIENT_ENTITY_ID,
    })
    expect(scope).toMatch(/^[A-Za-z0-9_-]{22}$/)
  })

  it('is stable for the same identity', () => {
    const identity = {
      appId: 'acme',
      environment: 'sandbox' as const,
      clientEntityId: CLIENT_ENTITY_ID,
    }
    expect(deriveKeyScope(identity)).toBe(deriveKeyScope({ ...identity }))
  })

  it('differs for two different clientEntityIds on the same appId/environment', () => {
    const scopeA = deriveKeyScope({
      appId: 'acme',
      environment: 'sandbox',
      clientEntityId: CLIENT_ENTITY_ID,
    })
    const scopeB = deriveKeyScope({
      appId: 'acme',
      environment: 'sandbox',
      clientEntityId: OTHER_CLIENT_ENTITY_ID,
    })
    expect(scopeA).not.toBe(scopeB)
  })

  it('never contains the raw clientEntityId', () => {
    const scope = deriveKeyScope({
      appId: 'acme',
      environment: 'sandbox',
      clientEntityId: CLIENT_ENTITY_ID,
    })
    expect(scope).not.toContain(CLIENT_ENTITY_ID)
    // Nor any hyphen-delimited fragment a UUID would leave if it were
    // simply concatenated rather than hashed.
    expect(scope).not.toMatch(/-/)
  })

  it('differs across appId and across environment for the same clientEntityId', () => {
    const base = {
      appId: 'acme',
      environment: 'sandbox' as const,
      clientEntityId: CLIENT_ENTITY_ID,
    }
    const differentApp = deriveKeyScope({ ...base, appId: 'other-app' })
    const differentEnv = deriveKeyScope({ ...base, environment: 'production' })
    const scope = deriveKeyScope(base)
    expect(differentApp).not.toBe(scope)
    expect(differentEnv).not.toBe(scope)
  })
})

describe('secureKeyAlias', () => {
  it('builds {appId}.{keyScope}.{environment} for valid input', () => {
    expect(
      secureKeyAlias({ appId: 'acme', environment: 'sandbox', clientEntityId: CLIENT_ENTITY_ID }),
    ).toBe(`acme.${ACME_SANDBOX_OWNER_1_SCOPE}.sandbox`)
  })

  it('rejects an empty or over-long appId', () => {
    expect(() =>
      secureKeyAlias({ appId: '', environment: 'sandbox', clientEntityId: CLIENT_ENTITY_ID }),
    ).toThrow(/appId must match/)
    expect(() =>
      secureKeyAlias({
        appId: 'a'.repeat(65),
        environment: 'sandbox',
        clientEntityId: CLIENT_ENTITY_ID,
      }),
    ).toThrow(/appId must match/)
  })

  it('rejects a disallowed character in appId', () => {
    expect(() =>
      secureKeyAlias({
        appId: 'acme/evil',
        environment: 'sandbox',
        clientEntityId: CLIENT_ENTITY_ID,
      }),
    ).toThrow(/appId must match/)
  })

  it('rejects an environment outside the allow-list', () => {
    expect(() =>
      secureKeyAlias({
        appId: 'acme',
        environment: 'Production' as never,
        clientEntityId: CLIENT_ENTITY_ID,
      }),
    ).toThrow(/unknown environment/)
  })

  it('rejects a clientEntityId that is not a UUID', () => {
    expect(() =>
      secureKeyAlias({ appId: 'acme', environment: 'sandbox', clientEntityId: 'not-a-uuid' }),
    ).toThrow(/clientEntityId must be a UUID/)
  })

  // Two different Owners on one installation resolve to different AuthKeys:
  // user A registers, signs out, user B signs in, and B's registration must
  // not reuse A's key.
  it('produces different aliases for different clientEntityIds on the same appId/environment', () => {
    const aliasA = secureKeyAlias({
      appId: 'acme',
      environment: 'sandbox',
      clientEntityId: CLIENT_ENTITY_ID,
    })
    const aliasB = secureKeyAlias({
      appId: 'acme',
      environment: 'sandbox',
      clientEntityId: OTHER_CLIENT_ENTITY_ID,
    })
    expect(aliasA).not.toBe(aliasB)
  })

  // A returning clientEntityId resolves to the SAME alias (and therefore, via
  // the store's alias-keyed cache/native tag, the SAME AuthKey) it did before.
  it('produces the same alias for a returning clientEntityId', () => {
    const identity = {
      appId: 'acme',
      environment: 'sandbox' as const,
      clientEntityId: CLIENT_ENTITY_ID,
    }
    expect(secureKeyAlias(identity)).toBe(secureKeyAlias({ ...identity }))
  })

  // The raw clientEntityId appears nowhere in the alias (and so nowhere in the
  // native keychain tag the alias's appId slot feeds).
  it('never contains the raw clientEntityId', () => {
    const alias = secureKeyAlias({
      appId: 'acme',
      environment: 'sandbox',
      clientEntityId: CLIENT_ENTITY_ID,
    })
    expect(alias).not.toContain(CLIENT_ENTITY_ID)
  })

  it('keeps appId/environment injective', () => {
    // Without environment validation, {"acme.staging","production"} and
    // {"acme","staging.production"} would both yield "acme.staging.production".
    // Validating `environment` makes the second impossible, with the per-Owner
    // keyScope segment in the alias as well.
    expect(
      secureKeyAlias({
        appId: 'acme.staging',
        environment: 'production',
        clientEntityId: CLIENT_ENTITY_ID,
      }),
    ).toBe(
      `acme.staging.${deriveKeyScope({ appId: 'acme.staging', environment: 'production', clientEntityId: CLIENT_ENTITY_ID })}.production`,
    )
    expect(() =>
      secureKeyAlias({
        appId: 'acme',
        environment: 'staging.production' as never,
        clientEntityId: CLIENT_ENTITY_ID,
      }),
    ).toThrow(/unknown environment/)
  })

  // Combined appId + digest over 64 characters fails closed with a contract
  // violation. The digest is a fixed 22 characters plus a 1-character
  // separator, so the appId budget is exactly 41.
  it('accepts an appId at exactly the 41-character budget', () => {
    const appId = 'a'.repeat(41)
    expect(() =>
      secureKeyAlias({ appId, environment: 'sandbox', clientEntityId: CLIENT_ENTITY_ID }),
    ).not.toThrow()
  })

  it('fails closed with a contract violation one character over the appId budget', () => {
    const appId = 'a'.repeat(42)
    expect(() =>
      secureKeyAlias({ appId, environment: 'sandbox', clientEntityId: CLIENT_ENTITY_ID }),
    ).toThrow(/at most 41 characters/)
  })

  // The 42-64 band must be rejected at the door by the same check that reports
  // the consumer-facing limit, not accepted here and refused later during key
  // resolution. Reverse-DNS bundle identifiers land squarely in this band.
  it('rejects the 42-64 band with the consumer-facing limit, not native 64', () => {
    expect(() =>
      secureKeyAlias({
        appId: 'com.example.digitalassetaccounts.wallet.debug',
        environment: 'sandbox',
        clientEntityId: CLIENT_ENTITY_ID,
      }),
    ).toThrow(/at most 41 characters/)
  })

  it('does not echo the full appId into the budget error message', () => {
    const appId = 'x'.repeat(60)
    expect.assertions(1)
    try {
      secureKeyAlias({ appId, environment: 'sandbox', clientEntityId: CLIENT_ENTITY_ID })
    } catch (e) {
      expect((e as Error).message).not.toContain(appId)
    }
  })

  it('does not echo the full appId into the pattern error message', () => {
    const long = 'x'.repeat(200)
    expect.assertions(1)
    try {
      secureKeyAlias({ appId: long, environment: 'sandbox', clientEntityId: CLIENT_ENTITY_ID })
    } catch (e) {
      expect((e as Error).message).not.toContain(long)
    }
  })
})

describe('parseSecureKeyAlias', () => {
  // NOT a full inverse of secureKeyAlias: deriveKeyScope is one-way,
  // so parsing an alias built from a real identity cannot recover
  // clientEntityId, and what it returns for "appId" is the composed
  // `{appId}.{keyScope}` native saw — not the consumer's original `appId`.
  it('recovers environment and the composed native appId, not the original identity', () => {
    const identity = {
      appId: 'acme.staging',
      environment: 'production' as const,
      clientEntityId: CLIENT_ENTITY_ID,
    }
    const alias = secureKeyAlias(identity)
    const scope = deriveKeyScope(identity)
    expect(parseSecureKeyAlias(alias)).toEqual({
      appId: `acme.staging.${scope}`,
      environment: 'production',
    })
  })

  // The composed value routinely exceeds the 41-character consumer budget (a
  // 23-char appId composes to 46), so this path must be validated against
  // native's 64, NOT against MAX_APP_ID_LENGTH. Enforcing the consumer cap
  // here would reject almost every real alias and break key resolution for
  // every existing Owner.
  it('accepts a composed appId longer than the consumer budget', () => {
    const identity = {
      appId: 'com.example.wallet.demo',
      environment: 'sandbox' as const,
      clientEntityId: CLIENT_ENTITY_ID,
    }
    const composed = `${identity.appId}.${deriveKeyScope(identity)}`
    expect(composed.length).toBe(46)
    expect(parseSecureKeyAlias(secureKeyAlias(identity))).toEqual({
      appId: composed,
      environment: 'sandbox',
    })
  })

  it('splits from the right so the last segment is the environment', () => {
    expect(parseSecureKeyAlias('acme.staging.production')).toEqual({
      appId: 'acme.staging',
      environment: 'production',
    })
  })

  it('rejects a value whose last segment is not an allowed environment', () => {
    expect(() => parseSecureKeyAlias('acme.sandbox.evil')).toThrow(/unknown environment/)
    expect(() => parseSecureKeyAlias('acme')).toThrow(/must be \{appId\}\.\{environment\}/)
  })

  it('does not echo the alias into the error message', () => {
    const long = `x${'y'.repeat(200)}.not-an-env`
    expect.assertions(1)
    try {
      parseSecureKeyAlias(long)
    } catch (e) {
      expect((e as Error).message).not.toContain(long)
    }
  })
})
