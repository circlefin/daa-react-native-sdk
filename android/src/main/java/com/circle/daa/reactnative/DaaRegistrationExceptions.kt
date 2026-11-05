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

import com.circle.daa.sdk.DaaRegistrationFlowKeyError
import com.circle.daa.sdk.DaaRegistrationFlowKeyException
import expo.modules.kotlin.exception.CodedException

internal class RegistrationContractViolationException :
    CodedException("CONTRACT_VIOLATION", "Native registration operation failed", null)

// No DaaSecureRandomError branch here, unlike the Swift mapper. That is a real
// platform divergence, not an omission: `SecRandomCopyBytes` returns a failable
// OSStatus, so daa-ios-sdk needs a DaaSecureRandomError type, while Kotlin's
// `SecureRandom.nextBytes` cannot fail and daa-android-sdk therefore declares no
// such type — there is nothing to match on. An invalid byte count arrives as
// IllegalArgumentException and is caught by the fallthrough below, which maps it
// to the same CONTRACT_VIOLATION the Swift side would produce. The JS-visible
// behaviour is identical; only the shape of the mapper differs.
internal fun mappedRegistrationException(error: Throwable): CodedException {
    if (error is CodedException) {
        return error
    }
    if (error is DaaRegistrationFlowKeyException) {
        return when (error.error) {
            DaaRegistrationFlowKeyError.KeyGenerationFailed,
            DaaRegistrationFlowKeyError.PublicKeyUnavailable,
            DaaRegistrationFlowKeyError.SigningFailed,
            -> RegistrationContractViolationException()
        }
    }
    return RegistrationContractViolationException()
}
