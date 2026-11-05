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

// Stable `code` values for mapNativeError. Reasons are canned — never copy
// Keychain / Secure Enclave text into the JS message.

internal final class UserAuthRequiredException: Exception, @unchecked Sendable {
  override var code: String { "USER_AUTH_REQUIRED" }
  override var reason: String { "User authentication is required" }
}

internal final class NotInitializedException: Exception, @unchecked Sendable {
  override var code: String { "NOT_INITIALIZED" }
  override var reason: String { "Secure key is not initialized" }
}

internal final class ContractViolationException: Exception, @unchecked Sendable {
  override var code: String { "CONTRACT_VIOLATION" }
  override var reason: String { "Native secure-key operation failed" }
}

internal func mappedSecureKeyException(_ error: Error) -> Exception {
  if let exception = error as? Exception {
    return exception
  }
  guard let keyError = error as? DaaSecureKeyError else {
    return ContractViolationException()
  }
  switch keyError {
  case .authenticationFailed, .userCancelled, .deviceLocked, .devicePasscodeNotSet:
    return UserAuthRequiredException()
  case .keyNotFound, .resolutionRequired:
    return NotInitializedException()
  case .invalidAppID,
       .invalidKeychainAccessGroup,
       .invalidSigningInput,
       .secureEnclaveUnavailable,
       .keyCreationFailed,
       .keyAccessFailed,
       .keychainEntitlementMissing,
       .keyMetadataUnavailable,
       .keyMetadataVersionUnsupported,
       .protectionMismatch,
       .publicKeyUnavailable,
       .operationCancelled,
       .signingAlgorithmUnavailable,
       .signingFailed,
       .authKeyRegistrationRequired,
       // protectionUnavailable is thrown for a DeviceUnlocked-protected key
       // signing a consequential operation — DeviceUnlocked itself is gated
       // behind @_spi, which this bridge never imports, so this is unreachable
       // from RN, same as the other cases in this bucket.
       // authKeyThumbprintMismatch is thrown when a registration device
       // proof's header jwk is not the signing key's own (its RFC 7638
       // thumbprint differs) — an upstream contract violation, not something
       // to retry.
       .protectionUnavailable,
       .authKeyThumbprintMismatch:
    return ContractViolationException()
  }
}
