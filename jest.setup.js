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

// Test-only: ensure a WebCrypto implementation is available on globalThis so the
// in-memory secure-key test double (P-256/ES256) works in the Jest node
// environment. Production/native code never imports node:crypto.
const { webcrypto } = require('node:crypto')

if (!globalThis.crypto) {
  globalThis.crypto = webcrypto
}

// Node has no Expo native module. Tests get a WebCrypto-backed fake for
// `DaaRegistration` (randomness, flow key, receipt signature verification) so
// production code can require the module without a silent JS fallback.
// `DaaSecureKey` stays absent unless a test injects it.
jest.mock('expo-modules-core', () => {
  const { generateKeyPairSync: generateEc, webcrypto: crypto } = require('node:crypto')
  const flowKeys = new Map()
  const jestDaaRegistration = {
    randomBytes(count) {
      const buf = crypto.getRandomValues(new Uint8Array(count))
      return Buffer.from(buf).toString('base64url')
    },
    randomUuidV4() {
      return crypto.randomUUID()
    },
    generateRegistrationFlowKey() {
      const { publicKey } = generateEc('ec', { namedCurve: 'prime256v1' })
      const spki = publicKey.export({ type: 'spki', format: 'der' })
      const id = crypto.randomUUID()
      flowKeys.set(id, Buffer.from(spki).toString('base64url'))
      return id
    },
    registrationFlowPublicKeySpkiBase64Url(id) {
      const encoded = flowKeys.get(id)
      if (typeof encoded !== 'string') {
        throw new Error(`no flow key ${id}`)
      }
      return encoded
    },
    releaseRegistrationFlowKey(id) {
      flowKeys.delete(id)
    },
    // Stand-in for native DaaPrepareReceiptSignature verification, with the same
    // contract: an uncompressed P-256 point the platform must accept (WebCrypto
    // rejects an off-curve point on import), exactly 64 bytes of JOSE R || S,
    // and a boolean result.
    async verifyPrepareReceiptSignature(publicKeyX963, signingInput, signature) {
      const point = Buffer.from(publicKeyX963, 'base64url')
      if (point.length !== 65 || point[0] !== 0x04) {
        throw new Error('not an uncompressed P-256 point')
      }
      const rs = Buffer.from(signature, 'base64url')
      if (rs.length !== 64) {
        return false
      }
      const key = await crypto.subtle.importKey(
        'raw',
        point,
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['verify'],
      )
      return crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        key,
        rs,
        Buffer.from(signingInput, 'base64url'),
      )
    },
  }
  return {
    requireOptionalNativeModule: jest.fn((name) => {
      if (name === 'DaaRegistration') {
        return jestDaaRegistration
      }
      return null
    }),
  }
})
