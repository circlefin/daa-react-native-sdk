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

package com.circle.daa.reactnative

import android.util.Base64

// Shared by DaaSecureKey and DaaRegistration. One canonicalization so a
// round-trip check on the signing-input decoder cannot drift from encode.

internal fun unpaddedBase64Url(bytes: ByteArray): String {
    return Base64.encodeToString(
        bytes,
        Base64.NO_WRAP or Base64.URL_SAFE or Base64.NO_PADDING,
    )
}

internal fun decodeUnpaddedBase64Url(encoded: String): ByteArray {
    if (encoded.length % 4 == 1) {
        throw ContractViolationException()
    }
    val decoded =
        try {
            Base64.decode(encoded, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        } catch (_: IllegalArgumentException) {
            throw ContractViolationException()
        }
    if (unpaddedBase64Url(decoded) != encoded) {
        throw ContractViolationException()
    }
    return decoded
}
