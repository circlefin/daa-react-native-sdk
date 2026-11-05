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

public class DaaSecureKeyModule: Module, @unchecked Sendable {
  private let cache = SecureKeyCache()

  public func definition() -> ModuleDefinition {
    Name("DaaSecureKey")
    let cache = self.cache

    // Mirrors `DEVICE_KEY_POLICY` in src/config.ts. This is a compiled-in
    // constant, not a live readback of a specific key's real Secure Enclave
    // protection: it is a version-skew guard between this module and the
    // TypeScript it ships with, so a mismatch means the two disagree about
    // the closed set, not that a key was inspected and found wanting. No
    // Keychain/Security API exposes the true `SecAccessControl` of an
    // existing key on iOS, so daa-ios-sdk's public `SecureKey` has no real
    // readback to expose here even in principle.
    Function("declaredKeyPolicy") { () -> [String: Any] in
      [
        "hardwareBacked": true,
        "userVerification": "REQUIRED_FOR_EACH_SIGNATURE",
      ]
    }

    AsyncFunction("resolveOrCreate") { (appId: String, environment: String) async throws -> String in
      do {
        let key = try await cache.secureKey(appId: appId, environment: environment)
        let resolution = try await key.resolveOrCreate()
        switch resolution {
        case .created:
          return "created"
        case .existing:
          return "existing"
        }
      } catch {
        throw mappedSecureKeyException(error)
      }
    }

    AsyncFunction("publicKeySpkiBase64Url") { (appId: String, environment: String) async throws -> String in
      do {
        let key = try await cache.secureKey(appId: appId, environment: environment)
        return try await key.publicKeySPKIBase64URL()
      } catch {
        throw mappedSecureKeyException(error)
      }
    }

    // Reached from OwnerAuthKey.acknowledgeRegistration() via the TS bridge.
    // This is the only registration-ack entry point; do not add a parallel one.
    AsyncFunction("acknowledgeRegistration") { (appId: String, environment: String) async throws in
      do {
        let key = try await cache.secureKey(appId: appId, environment: environment)
        try await key.acknowledgeRegistration()
      } catch {
        throw mappedSecureKeyException(error)
      }
    }

    // Typed native signDeviceAuthorization — not a generic sign(bytes). The
    // Base64URL payload is the exact compact-JWS signing input already built in
    // TypeScript; native validates those bytes and signs that same slice.
    // There is no prompt argument: DaaSdk sets all of the Face ID / Touch ID
    // text from the validated operation, and nothing here can change it.
    AsyncFunction("signDeviceAuthorization") { (
      appId: String,
      environment: String,
      signingInputBase64Url: String
    ) async throws -> String in
      do {
        let exactBytes = try decodeUnpaddedBase64URL(signingInputBase64Url)
        let signingInput = try DaaDeviceAuthorizationSigningInput(exactBytes: exactBytes)
        let key = try await cache.secureKey(appId: appId, environment: environment)
        let signature = try await key.signDeviceAuthorization(signingInput: signingInput)
        return unpaddedBase64URL(signature)
      } catch {
        throw mappedSecureKeyException(error)
      }
    }

    // Typed native signRegistrationDeviceAuthorization — the registration
    // counterpart of signDeviceAuthorization above, NOT the same call. The
    // Base64URL payload is the exact Device Registration Complete device-proof
    // signing input from `auth/registrationAuthorization.ts`; it is validated
    // by DaaRegistrationAuthorizationSigningInput, a different validator from
    // DaaDeviceAuthorizationSigningInput (registration `typ`s, an embedded
    // JWK header, no acknowledged-key gate). Do not route this input through
    // signDeviceAuthorization above, and do not route that input through here.
    // Like signDeviceAuthorization, it takes no prompt: DaaSdk shows its own
    // device-registration prompt text.
    AsyncFunction("signRegistrationDeviceAuthorization") { (
      appId: String,
      environment: String,
      signingInputBase64Url: String
    ) async throws -> String in
      do {
        let exactBytes = try decodeUnpaddedBase64URL(signingInputBase64Url)
        let signingInput = try DaaRegistrationAuthorizationSigningInput(exactBytes: exactBytes)
        let key = try await cache.secureKey(appId: appId, environment: environment)
        let signature = try await key.signRegistrationDeviceAuthorization(signingInput: signingInput)
        return unpaddedBase64URL(signature)
      } catch {
        throw mappedSecureKeyException(error)
      }
    }
  }
}

private actor SecureKeyCache {
  private var keys: [String: DaaSecureKey] = [:]
  private var installationID: UUID?

  func secureKey(appId: String, environment raw: String) throws -> DaaSecureKey {
    guard let environment = DaaEnvironment(rawValue: raw) else {
      throw ContractViolationException()
    }
    let alias = "\(appId).\(environment.rawValue)"
    if let existing = keys[alias] {
      return existing
    }
    let identity = try DaaAuthKeyIdentity(
      appID: appId,
      environment: environment,
      installationID: try installationUUID()
    )
    let key = DaaSecureKey(identity: identity)
    keys[alias] = key
    return key
  }

  private func installationUUID() throws -> UUID {
    if let installationID {
      return installationID
    }
    let id: UUID
    do {
      id = try InstallationIdentityStore.live().loadOrCreate()
    } catch {
      throw ContractViolationException()
    }
    installationID = id
    return id
  }
}
