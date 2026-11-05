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

import Foundation

// Shared by DaaSecureKey and DaaRegistration. One canonicalization so a
// round-trip check on the signing-input decoder cannot drift from encode.

func unpaddedBase64URL(_ data: Data) -> String {
  data.base64EncodedString()
    .replacingOccurrences(of: "+", with: "-")
    .replacingOccurrences(of: "/", with: "_")
    .replacingOccurrences(of: "=", with: "")
}

func decodeUnpaddedBase64URL(_ encoded: String) throws -> Data {
  guard encoded.count % 4 != 1 else {
    throw ContractViolationException()
  }
  let padding = String(repeating: "=", count: (4 - encoded.count % 4) % 4)
  let standard = encoded
    .replacingOccurrences(of: "-", with: "+")
    .replacingOccurrences(of: "_", with: "/")
  guard let decoded = Data(base64Encoded: standard + padding),
        unpaddedBase64URL(decoded) == encoded else {
    throw ContractViolationException()
  }
  return decoded
}
