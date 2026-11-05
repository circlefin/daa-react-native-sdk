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

// Cryptographically strong randomness.
//
// Production always goes through the Expo `DaaRegistration` module
// (`DaaSecureRandom` for verifier bytes, platform CSPRNG UUID for the attempt
// id). There is no host-WebCrypto fallback in these functions: a missing module
// is a `contract_violation`, including on a host that installed a WebCrypto
// polyfill for some other library.
//
// Node / Jest inject a fake native module in `jest.setup.js`. The explicit
// `webCryptoRandomBytes` / `webCryptoRandomUuidV4` helpers exist so tests can
// pin the stand-in; production callers never use them.
//
//   randomBytes   -> DaaSecureRandom.bytes
//   randomUuidV4  -> platform UUID
//
// A missing or non-functional source is a `contract_violation`, never a silent
// fallback. There is no `Math.random` path: the verifier is the secret binding
// Prepare to Registration Complete, and a predictable one defeats the handoff.

import {
  nativeRandomBytes,
  nativeRandomUuidV4,
  requireDaaRegistrationNative,
} from '../auth/daaRegistrationNative'
import { contractViolation } from '../errors'
import { isUuidV4 } from '../validation/uuid'

/** Fill a fresh buffer with `length` cryptographically strong random bytes. */
export function randomBytes(length: number): Uint8Array {
  if (!Number.isInteger(length) || length <= 0) {
    throw contractViolation('random byte length must be a positive integer')
  }
  return nativeRandomBytes(requireDaaRegistrationNative(), length)
}

/**
 * A random (version 4) UUID in the canonical hyphenated form, from the Expo
 * module's platform CSPRNG UUID. Re-checked so a stubbed native return fails
 * where the value is minted rather than as a rejected request later.
 */
export function randomUuidV4(): string {
  const uuid = nativeRandomUuidV4(requireDaaRegistrationNative())
  if (!isUuidV4(uuid)) {
    throw contractViolation('native randomUuidV4 did not return an RFC 4122 version 4 UUID')
  }
  return uuid
}

/**
 * Node/Jest stand-in for verifier bytes. Production `randomBytes` never calls
 * this; tests that pin host WebCrypto import it explicitly.
 */
export function webCryptoRandomBytes(length: number): Uint8Array {
  if (!Number.isInteger(length) || length <= 0) {
    throw contractViolation('random byte length must be a positive integer')
  }
  const getRandomValues = hostFunction('getRandomValues')
  const buffer = new Uint8Array(length)
  getRandomValues(buffer)
  return buffer
}

/**
 * Node/Jest stand-in for the attempt UUID. Production `randomUuidV4` never
 * calls this; tests that pin `crypto.randomUUID` import it explicitly.
 */
export function webCryptoRandomUuidV4(): string {
  const uuid = hostFunction('randomUUID')()
  if (!isUuidV4(uuid)) {
    throw contractViolation('crypto.randomUUID did not return an RFC 4122 version 4 UUID')
  }
  return uuid
}

// Resolve one WebCrypto function by name, or fail closed naming it.
//
// `globalThis.crypto` is read per call rather than captured at import, so a host
// that installs its polyfill after this module is first evaluated is still
// served. One message shape for every missing function, so a caller (and a test)
// can tell exactly which one the host did not supply.
//
// Bound to the host object: both functions are specified to reject a foreign
// receiver (`TypeError: Value of "this" must be of type Crypto`), so returning
// them detached would throw at the call site instead of working.
function hostFunction<K extends 'getRandomValues' | 'randomUUID'>(name: K): NonNullable<Crypto[K]> {
  const host = (globalThis as { crypto?: Crypto }).crypto
  if (host === undefined || typeof host[name] !== 'function') {
    throw contractViolation(
      `crypto.${name} is required to mint login-attempt material; ` +
        'install a WebCrypto implementation that provides it in the host app',
    )
  }
  const fn = host[name] as NonNullable<Crypto[K]>
  return fn.bind(host) as NonNullable<Crypto[K]>
}
