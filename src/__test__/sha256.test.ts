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

import { toBase64Url } from '../crypto/base64url'
import { toArrayBuffer } from '../crypto/bytes'
import { sha256 } from '../crypto/sha256'
import { AUTH_KEY_WIRE_V1_SHA256, readAuthKeyWireFixtureBytes } from './authKeyWireFixture'

function hex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

describe('sha256', () => {
  it('matches known FIPS 180-4 vectors', () => {
    expect(hex(sha256(new TextEncoder().encode('')))).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    )
    expect(hex(sha256(new TextEncoder().encode('abc')))).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    )
    // 56-byte input exercises the two-block padding path.
    expect(
      hex(
        sha256(
          new TextEncoder().encode('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'),
        ),
      ),
    ).toBe('248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1')
  })

  it('agrees with WebCrypto across every length through two blocks', async () => {
    // Exhaustive so every padding path is covered, incl. the 55/56 and 64/128
    // block-boundary transitions where the length math is easiest to get wrong.
    for (let len = 0; len <= 130; len++) {
      const bytes = new Uint8Array(len)
      for (let i = 0; i < len; i++) bytes[i] = (i * 31 + 7) & 0xff
      const ref = new Uint8Array(
        await globalThis.crypto.subtle.digest('SHA-256', toArrayBuffer(bytes)),
      )
      expect(toBase64Url(sha256(bytes))).toBe(toBase64Url(ref))
    }
  })

  it('matches the published digest of the canonical AuthKeyWireV1 fixture', () => {
    // The fixture carries no standalone digest vector, but its own published
    // SHA-256 is one: a multi-kilobyte, many-block input whose expected digest
    // is fixed by daa-ios-sdk and independently asserted by daa-android-sdk.
    // This is also what makes the loader's drift guard trustworthy.
    expect(hex(sha256(readAuthKeyWireFixtureBytes()))).toBe(AUTH_KEY_WIRE_V1_SHA256)
  })
})
