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

import { fromBase64Url, toBase64Url } from '../crypto/base64url'
import { toArrayBuffer } from '../crypto/bytes'
import { p256JwkThumbprint } from '../crypto/jwkThumbprint'
import { bytesToHex, loadAuthKeyWireFixture, namedHex } from './authKeyWireFixture'

describe('p256JwkThumbprint', () => {
  it('rejects anything that is not a 91-byte P-256 SPKI', () => {
    expect(() => p256JwkThumbprint(new Uint8Array(65))).toThrow(/91-byte P-256 SPKI/)
  })

  it('matches a WebCrypto-derived RFC 7638 thumbprint', async () => {
    const kp = (await globalThis.crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify'],
    )) as CryptoKeyPair
    const spki = new Uint8Array(await globalThis.crypto.subtle.exportKey('spki', kp.publicKey))
    const jwk = (await globalThis.crypto.subtle.exportKey('jwk', kp.publicKey)) as JsonWebKey
    const canonical = `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}`
    const reference = toBase64Url(
      new Uint8Array(
        await globalThis.crypto.subtle.digest(
          'SHA-256',
          toArrayBuffer(new TextEncoder().encode(canonical)),
        ),
      ),
    )
    // Validates both the SPKI x/y slicing and the vendored SHA-256 end-to-end.
    expect(p256JwkThumbprint(spki)).toBe(reference)
  })
})

// The generated-key test above proves this implementation agrees with itself and
// with WebCrypto. These pin it to the canonical cross-language vectors instead,
// so the TypeScript `jkt` cannot drift from the iOS and Android SDKs.
describe('p256JwkThumbprint against the canonical AuthKeyWireV1 vectors', () => {
  const fixture = loadAuthKeyWireFixture()
  const spki = fromBase64Url(fixture.p256PublicKey.spkiBase64Url)

  it('derives the canonical RFC 7638 thumbprint from the canonical SPKI', () => {
    expect(spki.length).toBe(91)
    expect(p256JwkThumbprint(spki)).toBe(fixture.p256PublicKey.jwkThumbprint)
  })

  it('slices x and y from the offset the canonical X9.63 point occupies', () => {
    // Pins the hard-coded offset 26: everything from there must be the 65-byte
    // uncompressed point the fixture publishes separately as `x963Hex`.
    expect(bytesToHex(spki.subarray(26))).toBe(fixture.p256PublicKey.x963Hex)
  })

  it('rejects the canonical malformed SPKI encodings it can detect', () => {
    for (const name of ['truncated', 'overlong']) {
      const vector = namedHex(fixture.rejected.subjectPublicKeyInfo, name)
      expect(() => p256JwkThumbprint(vector)).toThrow(/91-byte P-256 SPKI/)
    }
  })

  it('rejects a bare X9.63 point, which is not a SubjectPublicKeyInfo', () => {
    // `compressed` is caught by the point marker as well as the length; the
    // other two are only ever caught by the length check, because this function
    // accepts an SPKI and never a bare point.
    for (const name of ['compressed', 'invalid-marker', 'off-curve']) {
      const vector = namedHex(fixture.rejected.x963PublicKeys, name)
      expect(() => p256JwkThumbprint(vector)).toThrow(/91-byte P-256 SPKI/)
    }
  })
})
