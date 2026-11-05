// Copyright (c) 2026, Circle Internet Group, Inc. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import DaaSdk
import ExpoModulesCore
import Foundation

// Thin Expo bridge to the native registration primitives. THIS IS NOT
// DaaSecureKey. Verifier bytes come from DaaSecureRandom; the ephemeral
// flow key is DaaRegistrationFlowKey, cached here so the private key never
// crosses into JavaScript; the Prepare receipt signature is checked by
// DaaPrepareReceiptSignature.

public class DaaRegistrationModule: Module {
  private let flowKeys = RegistrationFlowKeyCache()

  public func definition() -> ModuleDefinition {
    Name("DaaRegistration")

    Function("randomBytes") { (count: Int) throws -> String in
      do {
        return unpaddedBase64URL(try DaaSecureRandom.bytes(count: count))
      } catch {
        throw mappedRegistrationException(error)
      }
    }

    Function("randomUuidV4") { () -> String in
      UUID().uuidString.lowercased()
    }

    Function("generateRegistrationFlowKey") { () -> String in
      flowKeys.store(DaaRegistrationFlowKey.generate())
    }

    Function("registrationFlowPublicKeySpkiBase64Url") { (id: String) throws -> String in
      do {
        return try flowKeys.publicKeySPKIBase64URL(id: id)
      } catch {
        throw mappedRegistrationException(error)
      }
    }

    // Drops the cached key so its private half is no longer reachable and can be
    // released. Without this the cache grows by one P-256 private key per login
    // attempt and never shrinks, which contradicts the point of generating the
    // key natively: shortening how long key material is resident. Idempotent,
    // and deliberately silent about an unknown id — release is cleanup, and a
    // caller releasing twice (or in a `finally` after a failure) must not turn
    // tidying up into an error.
    Function("releaseRegistrationFlowKey") { (id: String) -> Void in
      flowKeys.release(id: id)
    }

    // Typed native signRegistrationAuthorization — not a generic sign(bytes).
    // The Base64URL payload is the exact Device Registration Complete flow-JWS
    // signing input already built in TypeScript; native validates those bytes
    // and signs that same slice. Synchronous and prompt-free: the flow key is
    // in process memory, not the Secure Enclave, so there is no biometric gate.
    Function("signRegistrationAuthorization") { (id: String, signingInputBase64Url: String) throws -> String in
      do {
        let exactBytes = try decodeUnpaddedBase64URL(signingInputBase64Url)
        let signingInput = try DaaRegistrationAuthorizationSigningInput(exactBytes: exactBytes)
        let signature = try flowKeys.signRegistrationAuthorization(id: id, signingInput: signingInput)
        return unpaddedBase64URL(signature)
      } catch {
        throw mappedRegistrationException(error)
      }
    }

    // Verify-only, against a key JS pinned from the SDK's own trust anchor —
    // never a key from the token. DaaPrepareReceiptSignature (daa-ios-sdk) does
    // the check with CryptoKit: a signature problem is `false`, and a key that
    // is not a P-256 point throws and maps to CONTRACT_VIOLATION.
    AsyncFunction("verifyPrepareReceiptSignature") {
      (publicKeyX963Base64Url: String, signingInputBase64Url: String, signatureBase64Url: String) throws -> Bool in
      do {
        return try DaaPrepareReceiptSignature.verify(
          publicKeyX963: try decodeUnpaddedBase64URL(publicKeyX963Base64Url),
          signingInput: try decodeUnpaddedBase64URL(signingInputBase64Url),
          signature: try decodeUnpaddedBase64URL(signatureBase64Url)
        )
      } catch {
        throw mappedRegistrationException(error)
      }
    }
  }
}

private final class RegistrationFlowKeyCache: @unchecked Sendable {
  private let lock = NSLock()
  private var keys: [String: DaaRegistrationFlowKey] = [:]

  func store(_ key: DaaRegistrationFlowKey) -> String {
    let id = UUID().uuidString.lowercased()
    lock.lock()
    keys[id] = key
    lock.unlock()
    return id
  }

  func publicKeySPKIBase64URL(id: String) throws -> String {
    lock.lock()
    let key = keys[id]
    lock.unlock()
    guard let key else {
      throw RegistrationContractViolationException()
    }
    return try key.publicKeySPKIBase64URL()
  }

  func release(id: String) {
    lock.lock()
    keys.removeValue(forKey: id)
    lock.unlock()
  }

  func signRegistrationAuthorization(
    id: String,
    signingInput: DaaRegistrationAuthorizationSigningInput
  ) throws -> Data {
    lock.lock()
    let key = keys[id]
    lock.unlock()
    guard let key else {
      throw RegistrationContractViolationException()
    }
    return try key.signRegistrationAuthorization(signingInput: signingInput)
  }
}
