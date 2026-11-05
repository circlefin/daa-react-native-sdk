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

// Stable `code` values for the JS wrapper. Reasons are canned — never copy
// CSPRNG / key-generation text into the JS message. Distinct from the
// AuthKey mapper: this module never touches DaaSecureKey.

internal final class RegistrationContractViolationException: Exception {
  override var code: String { "CONTRACT_VIOLATION" }
  override var reason: String { "Native registration operation failed" }
}

internal func mappedRegistrationException(_ error: Error) -> Exception {
  if let exception = error as? Exception {
    return exception
  }
  if let randomError = error as? DaaSecureRandomError {
    switch randomError {
    case .invalidByteCount, .randomnessUnavailable:
      return RegistrationContractViolationException()
    }
  }
  if let flowError = error as? DaaRegistrationFlowKeyError {
    // Every case maps the same way: this bridge discloses no distinction
    // between flow-key error causes to JS. The switch is exhaustive against
    // the pinned DaaSdk, so a DaaSdk release that adds a case fails to compile
    // here with `switch must be exhaustive`.
    switch flowError {
    case .publicKeyUnavailable, .signingFailed, .invalidSigningInput:
      return RegistrationContractViolationException()
    }
  }
  // DaaRegistrationAuthorizationSigningInput's initializer validates against
  // the shared AuthKey error type rather than declaring its own, since the
  // validated-input shape is shared with DaaSecureKey. Named explicitly here
  // (rather than left to the generic fallthrough below) so a reader can see
  // this module already accounts for it.
  if let secureKeyError = error as? DaaSecureKeyError, secureKeyError == .invalidSigningInput {
    return RegistrationContractViolationException()
  }
  return RegistrationContractViolationException()
}
