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
import { bytesToHex, hexToBytes, loadAuthKeyWireFixture } from './authKeyWireFixture'

describe('base64url', () => {
  it('encodes without padding and using the URL-safe alphabet', () => {
    // 0xFF 0xFE 0xFD -> standard "//79", URL-safe "__79"
    expect(toBase64Url(new Uint8Array([0xff, 0xfe, 0xfd]))).toBe('__79')
  })

  it('encodes the empty array as the empty string', () => {
    expect(toBase64Url(new Uint8Array([]))).toBe('')
  })

  it('round-trips arbitrary byte lengths', () => {
    for (let len = 0; len < 40; len++) {
      const bytes = new Uint8Array(len)
      for (let i = 0; i < len; i++) bytes[i] = (i * 37 + 11) & 0xff
      expect(Array.from(fromBase64Url(toBase64Url(bytes)))).toEqual(Array.from(bytes))
    }
  })

  it('rejects invalid input', () => {
    expect(() => fromBase64Url('****')).toThrow(/invalid Base64URL/)
  })

  it('rejects an impossible length (len % 4 === 1)', () => {
    expect(() => fromBase64Url('A')).toThrow(/invalid Base64URL length/)
  })

  it('rejects a non-canonical encoding with non-zero trailing bits', () => {
    expect(() => fromBase64Url('AB')).toThrow(/non-canonical/)
  })
})

// The only Base64URL value the canonical fixture publishes is the P-256 SPKI, so
// this is the shared wire-encoding vector the three SDKs have in common.
describe('base64url against the canonical AuthKeyWireV1 vectors', () => {
  const fixture = loadAuthKeyWireFixture()
  const { spkiBase64Url, x963Hex } = fixture.p256PublicKey

  it('decodes the canonical SPKI to 91 bytes ending in the canonical point', () => {
    const spki = fromBase64Url(spkiBase64Url)
    expect(spki.length).toBe(91)
    expect(bytesToHex(spki.subarray(26))).toBe(x963Hex)
  })

  it('re-encodes the canonical SPKI to the exact published string', () => {
    // Encoding is the direction that reaches the wire, so this pins the
    // unpadded URL-safe alphabet against a value iOS and Android also produce.
    expect(toBase64Url(fromBase64Url(spkiBase64Url))).toBe(spkiBase64Url)
    expect(spkiBase64Url).not.toContain('=')
  })

  it('round-trips every hex-encoded vector in the fixture', () => {
    const vectors = [
      x963Hex,
      fixture.signedMessage.messageHex,
      fixture.signedMessage.derHex,
      fixture.signedMessage.rawHex,
      ...fixture.ecdsaSignatures.flatMap((signature) => [signature.derHex, signature.rawHex]),
      ...fixture.rejected.ecdsaDer.map((vector) => vector.hex),
      ...fixture.rejected.ecdsaRaw.map((vector) => vector.hex),
    ]
    for (const hex of vectors) {
      const bytes = hexToBytes(hex)
      expect(bytesToHex(fromBase64Url(toBase64Url(bytes)))).toBe(hex)
    }
  })
})
