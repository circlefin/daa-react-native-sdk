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

import { requireOptionalNativeModule } from 'expo-modules-core'
import { fromBase64Url, toBase64Url } from '../crypto/base64url'
import { contractViolation, isDaaError } from '../errors'

// JS shape of the Expo `DaaRegistration` native module. Separate from
// `DaaSecureKey`: this module bridges DaaSecureRandom, DaaRegistrationFlowKey,
// and platform verification of the Prepare receipt signature. The flow-key
// private key stays in the native cache keyed by the handle id; only Base64URL
// strings cross the bridge.

export const DAA_REGISTRATION_MODULE = 'DaaRegistration'

export interface DaaRegistrationNativeModule {
  randomBytes(count: number): string
  randomUuidV4(): string
  generateRegistrationFlowKey(): string
  registrationFlowPublicKeySpkiBase64Url(id: string): string
  releaseRegistrationFlowKey(id: string): void
  /**
   * Typed Complete-only sign — not a generic `sign(bytes)`. `signingInputBase64Url`
   * is the exact Device Registration Complete flow-JWS signing input; the native
   * module validates those bytes and signs that same slice with the cached flow
   * key, returning unpadded Base64URL of the 64-byte JOSE `R || S` signature.
   */
  signRegistrationAuthorization(id: string, signingInputBase64Url: string): string
  /**
   * Native ES256 verification of a Prepare receipt signature, delegated to the
   * native SDKs' `DaaPrepareReceiptSignature` (CryptoKit on iOS,
   * `java.security` on Android). All three arguments are unpadded
   * Base64URL — the uncompressed P-256 point of a pinned key, the exact JWS
   * signing input, and the 64-byte JOSE `R || S` signature. Resolves `true`
   * only for a valid signature; rejects when the key is not a P-256 point.
   */
  verifyPrepareReceiptSignature(
    publicKeyX963Base64Url: string,
    signingInputBase64Url: string,
    signatureBase64Url: string,
  ): Promise<boolean>
}

export function optionalDaaRegistrationNative(): DaaRegistrationNativeModule | null {
  const native = requireOptionalNativeModule<DaaRegistrationNativeModule>(DAA_REGISTRATION_MODULE)
  if (native == null) {
    return null
  }
  return native
}

export function requireDaaRegistrationNative(): DaaRegistrationNativeModule {
  const native = optionalDaaRegistrationNative()
  if (native === null) {
    throw contractViolation(
      'native DaaRegistration module is not available to mint or verify login-attempt material; ' +
        'include the DaaRegistration Expo module in the host app',
    )
  }
  return native
}

function nativeCall<T>(op: () => T): T {
  try {
    return op()
  } catch (err) {
    if (isDaaError(err)) {
      throw err
    }
    throw contractViolation('native DaaRegistration operation failed')
  }
}

/** Verifier bytes from native `DaaSecureRandom`, decoded at the seam. */
export function nativeRandomBytes(native: DaaRegistrationNativeModule, count: number): Uint8Array {
  if (typeof native.randomBytes !== 'function') {
    throw contractViolation('native DaaRegistration.randomBytes is required')
  }
  const encoded = nativeCall(() => native.randomBytes(count))
  if (typeof encoded !== 'string') {
    throw contractViolation('native DaaSecureRandom did not return Base64URL')
  }
  let bytes: Uint8Array
  try {
    bytes = fromBase64Url(encoded)
  } catch {
    throw contractViolation('native DaaSecureRandom did not return valid Base64URL')
  }
  if (bytes.length !== count) {
    throw contractViolation(
      `native DaaSecureRandom must return ${count} bytes; got ${bytes.length}`,
    )
  }
  return bytes
}

export function nativeRandomUuidV4(native: DaaRegistrationNativeModule): string {
  if (typeof native.randomUuidV4 !== 'function') {
    throw contractViolation('native DaaRegistration.randomUuidV4 is required')
  }
  const uuid = nativeCall(() => native.randomUuidV4())
  if (typeof uuid !== 'string') {
    throw contractViolation('native randomUuidV4 did not return a string')
  }
  return uuid
}

export function nativeGenerateRegistrationFlowKey(native: DaaRegistrationNativeModule): string {
  if (typeof native.generateRegistrationFlowKey !== 'function') {
    throw contractViolation('native DaaRegistration.generateRegistrationFlowKey is required')
  }
  const id = nativeCall(() => native.generateRegistrationFlowKey())
  if (typeof id !== 'string' || id.length === 0) {
    throw contractViolation('native generateRegistrationFlowKey did not return a handle id')
  }
  return id
}

export function nativeRegistrationFlowPublicKeySpkiBase64Url(
  native: DaaRegistrationNativeModule,
  id: string,
): string {
  if (typeof native.registrationFlowPublicKeySpkiBase64Url !== 'function') {
    throw contractViolation(
      'native DaaRegistration.registrationFlowPublicKeySpkiBase64Url is required',
    )
  }
  const spki = nativeCall(() => native.registrationFlowPublicKeySpkiBase64Url(id))
  if (typeof spki !== 'string') {
    throw contractViolation('native registration-flow public key did not return a string')
  }
  return spki
}

/**
 * Sign the exact Device Registration Complete flow-JWS signing input with the
 * cached native flow key. Returns unpadded Base64URL of the 64-byte JOSE
 * `R || S` signature. Not a generic sign: `id` names a cached
 * `DaaRegistrationFlowKey`, and native validates the bytes as a registration
 * authorization signing input before it ever touches the private key.
 */
export function nativeSignRegistrationAuthorization(
  native: DaaRegistrationNativeModule,
  id: string,
  signingInputBase64Url: string,
): Uint8Array {
  if (typeof native.signRegistrationAuthorization !== 'function') {
    throw contractViolation('native DaaRegistration.signRegistrationAuthorization is required')
  }
  const signature = nativeCall(() =>
    native.signRegistrationAuthorization(id, signingInputBase64Url),
  )
  if (typeof signature !== 'string') {
    throw contractViolation('native registration-flow signature did not return a string')
  }
  let bytes: Uint8Array
  try {
    bytes = fromBase64Url(signature)
  } catch {
    throw contractViolation('native registration-flow signature is not valid Base64URL')
  }
  if (bytes.length !== 64) {
    throw contractViolation(
      `native registration-flow signature must be 64 bytes (JOSE R||S); got ${bytes.length}`,
    )
  }
  return bytes
}

/**
 * Verify one ES256 signature with platform crypto.
 *
 * Only a literal `true` from native counts as verified. Anything else — `false`,
 * a non-boolean, a rejection, a missing function on an older host build — is
 * not a pass: a rejection or a missing function is a `contract_violation`, and
 * any other value is `false`.
 */
export async function nativeVerifyPrepareReceiptSignature(
  native: DaaRegistrationNativeModule,
  args: Readonly<{ publicKeyX963: Uint8Array; signingInput: Uint8Array; signature: Uint8Array }>,
): Promise<boolean> {
  if (typeof native.verifyPrepareReceiptSignature !== 'function') {
    throw contractViolation('native DaaRegistration.verifyPrepareReceiptSignature is required')
  }
  let result: unknown
  try {
    result = await native.verifyPrepareReceiptSignature(
      toBase64Url(args.publicKeyX963),
      toBase64Url(args.signingInput),
      toBase64Url(args.signature),
    )
  } catch (err) {
    if (isDaaError(err)) {
      throw err
    }
    throw contractViolation('native Prepare receipt signature verification failed')
  }
  return result === true
}

/**
 * Drop a cached native flow key.
 *
 * Cleanup, so it is forgiving: an older host app whose module predates this
 * function, or an id the native side no longer holds, is not an error. The
 * alternative would make a `finally` block throw over tidying up and mask the
 * failure that sent it there. What it must not do is fail silently in a way
 * that leaves key material resident — hence the explicit function check rather
 * than an optional-call shrug.
 */
export function nativeReleaseRegistrationFlowKey(
  native: DaaRegistrationNativeModule,
  id: string,
): void {
  if (typeof native.releaseRegistrationFlowKey !== 'function') {
    return
  }
  nativeCall(() => {
    native.releaseRegistrationFlowKey(id)
  })
}
