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

// The codes match the Android bridge exactly, so the TypeScript layer maps one
// vocabulary. A reason, where there is one, rides in the code as
// "<CODE>:<Reason>". An async function's rejection reaches JS without the
// exception's code, and Expo wraps its message ("Calling the 'approve' function
// has failed → Caused by: …"), so the message also starts with the code in
// brackets; the TypeScript layer reads it from the innermost cause.

private func tagged(_ code: String, _ detail: String) -> String {
  "[\(code)] \(detail)"
}

internal final class ScaCancelledException: Exception {
  override var code: String { "SCA_CANCELLED" }
  override var reason: String { tagged(code, "The ceremony was cancelled") }
}

internal final class ScaFailedException: Exception {
  private let scaCode: String
  private let detail: String

  init(code: String, detail: String) {
    self.scaCode = code
    self.detail = detail
    super.init()
  }

  override var code: String { scaCode }
  override var reason: String { tagged(code, detail) }
}

internal final class ScaInvalidConfigurationException: Exception {
  private let detail: String

  init(_ detail: String) {
    self.detail = detail
    super.init()
  }

  override var code: String { "SCA_INVALID_CONFIGURATION" }
  override var reason: String { tagged(code, detail) }
}

internal final class ScaCeremonyInProgressException: Exception {
  override var code: String { "SCA_CEREMONY_IN_PROGRESS" }
  override var reason: String { tagged(code, "Another SCA ceremony is still open") }
}

internal func mappedScaException(_ error: Error) -> Exception {
  if let exception = error as? Exception {
    return exception
  }
  guard let scaError = error as? DaaScaError else {
    return ScaFailedException(code: "SCA_PROTOCOL", detail: "Unexpected native error")
  }
  switch scaError {
  case .cancelled:
    return ScaCancelledException()
  case let .expired(message):
    return ScaFailedException(code: "SCA_EXPIRED", detail: message ?? "The ceremony expired")
  case let .unsupported(message):
    return ScaFailedException(code: "SCA_UNSUPPORTED:PasskeyUnavailable", detail: message ?? "Passkeys are unavailable")
  case let .alreadyEnrolled(message):
    return ScaFailedException(code: "SCA_ALREADY_ENROLLED", detail: message ?? "A passkey is already enrolled")
  case .stateMismatch:
    return ScaFailedException(code: "SCA_PROTOCOL:StateMismatch", detail: "The callback did not belong to this ceremony")
  case let .sessionUnavailable(message):
    return ScaFailedException(code: "SCA_UNSUPPORTED:SessionUnavailable", detail: message ?? "No session could be presented")
  case let .protocol(message):
    // The SDK checks the frame token before opening anything; those are caller
    // bugs, reported the same way as Android's argument checks.
    if let message, message.hasPrefix("frameToken") {
      return ScaFailedException(code: "SCA_PROTOCOL:InvalidFrameToken", detail: message)
    }
    return ScaFailedException(code: "SCA_PROTOCOL", detail: message ?? "Protocol error")
  }
}

