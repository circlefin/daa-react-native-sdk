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

// Test-only loader for the canonical cross-language AuthKey wire fixture
// (`daa-authkey-wire-v1`).
//
// `daa-ios-sdk` owns the artifact at `Conformance/AuthKeyWireV1.json`, and the
// AuthKey wire contract requires every DAA SDK to consume that same
// artifact — a locally generated substitute does not satisfy cross-platform
// conformance. `fixtures/AuthKeyWireV1.json` is therefore a byte-for-byte copy
// (never reformatted; see `.prettierignore`), and this loader pins its SHA-256
// so a local edit fails the suite instead of silently diverging from iOS and
// Android. `daa-android-sdk` guards its copy the same way in
// `AuthKeyWireFixture.kt`.
//
// This file is not a test (`testMatch` is `**/__test__/**/*.test.ts`) and never
// ships: `tsconfig.build.json` and `package.json#files` both exclude `__test__`.

import { readFileSync } from 'node:fs'

import { sha256 } from '../crypto/sha256'

/** SHA-256 of the canonical `AuthKeyWireV1.json`, as published by `daa-ios-sdk`. */
export const AUTH_KEY_WIRE_V1_SHA256 =
  'fc1d3f78b19269872aa75433a3ea14932a947a99af4c76329aca15bc867bf6ff'

const EXPECTED_PROFILE = 'daa-authkey-wire-v1'
const EXPECTED_CONTRACT = 'docs/authkey-wire-contract.md'

export type AuthKeyWireNamedHex = Readonly<{
  name: string
  hex: string
}>

export type AuthKeyWireFixture = Readonly<{
  profile: string
  contract: string
  p256PublicKey: Readonly<{
    x963Hex: string
    spkiBase64Url: string
    jwkThumbprint: string
  }>
  signedMessage: Readonly<{
    name: string
    messageHex: string
    publicKeyX963Hex: string
    derHex: string
    rawHex: string
  }>
  ecdsaSignatures: readonly Readonly<{
    name: string
    derHex: string
    rawHex: string
  }>[]
  rejected: Readonly<{
    ecdsaDer: readonly AuthKeyWireNamedHex[]
    ecdsaRaw: readonly AuthKeyWireNamedHex[]
    x963PublicKeys: readonly AuthKeyWireNamedHex[]
    subjectPublicKeyInfo: readonly AuthKeyWireNamedHex[]
  }>
}>

/** Lower-case hex, for comparing against the fixture's hex-encoded vectors. */
export function bytesToHex(bytes: Uint8Array): string {
  let out = ''
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i]!.toString(16).padStart(2, '0')
  }
  return out
}

/** Decode one of the fixture's lower-case hex vectors. */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error(`AuthKeyWireV1: hex vector has an odd length: ${hex.length}`)
  }
  // Asserted over the whole string rather than per byte: `Number.parseInt`
  // stops at the first invalid character instead of failing, so
  // `Number.parseInt('1z', 16)` is 1 — a bad second nibble would decode as the
  // first nibble's value and never reach a NaN check.
  if (!/^[0-9a-f]*$/.test(hex)) {
    throw new Error('AuthKeyWireV1: hex vector has a non-hex character')
  }
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

/**
 * The vendored fixture's raw bytes, read without the digest guard so a caller
 * can assert the digest itself.
 */
export function readAuthKeyWireFixtureBytes(): Uint8Array {
  return new Uint8Array(readFileSync(`${__dirname}/fixtures/AuthKeyWireV1.json`))
}

/**
 * Load the canonical fixture, failing if the vendored copy has drifted.
 *
 * The digest is computed with this SDK's own vendored `sha256` rather than a
 * Node dependency (`crypto` is not available to production React Native code,
 * and this SDK adds no Node dependency). That is only self-referential in
 * appearance: `sha256.test.ts` pins the same implementation against the FIPS
 * 180-4 vectors and, exhaustively through two blocks, against WebCrypto — so a
 * broken digest cannot quietly ratify a broken fixture.
 */
export function loadAuthKeyWireFixture(): AuthKeyWireFixture {
  const bytes = readAuthKeyWireFixtureBytes()
  const digest = bytesToHex(sha256(bytes))
  if (digest !== AUTH_KEY_WIRE_V1_SHA256) {
    throw new Error(
      `AuthKeyWireV1.json is not the canonical artifact: expected SHA-256 ` +
        `${AUTH_KEY_WIRE_V1_SHA256}, got ${digest}. Re-copy it byte-for-byte from ` +
        `daa-ios-sdk/Conformance/AuthKeyWireV1.json; do not re-serialize it.`,
    )
  }

  const fixture = JSON.parse(new TextDecoder().decode(bytes)) as AuthKeyWireFixture

  // Metadata and vector counts are checked the same way the Android loader
  // checks them, so a future fixture revision that keeps the shape but drops a
  // vector cannot silently shrink this suite's coverage.
  if (fixture.profile !== EXPECTED_PROFILE || fixture.contract !== EXPECTED_CONTRACT) {
    throw new Error(`AuthKeyWireV1.json metadata drifted: ${fixture.profile} / ${fixture.contract}`)
  }
  const counts: readonly [string, number, number][] = [
    ['ecdsaSignatures', fixture.ecdsaSignatures.length, 3],
    ['rejected.ecdsaDer', fixture.rejected.ecdsaDer.length, 3],
    ['rejected.ecdsaRaw', fixture.rejected.ecdsaRaw.length, 6],
    ['rejected.x963PublicKeys', fixture.rejected.x963PublicKeys.length, 3],
    ['rejected.subjectPublicKeyInfo', fixture.rejected.subjectPublicKeyInfo.length, 4],
  ]
  for (const [name, actual, expected] of counts) {
    if (actual !== expected) {
      throw new Error(`AuthKeyWireV1.json ${name}: expected ${expected} vectors, got ${actual}`)
    }
  }

  return fixture
}

/** Look up a named vector, so a test names the case it is asserting. */
export function namedHex(vectors: readonly AuthKeyWireNamedHex[], name: string): Uint8Array {
  const vector = vectors.find((candidate) => candidate.name === name)
  if (!vector) {
    throw new Error(`AuthKeyWireV1.json is missing the "${name}" vector`)
  }
  return hexToBytes(vector.hex)
}
