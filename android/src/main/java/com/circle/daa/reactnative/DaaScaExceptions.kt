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

import com.circle.daa.sdk.sca.DaaScaError
import com.circle.daa.sdk.sca.DaaScaResult
import expo.modules.kotlin.exception.CodedException

// JS reads `error.code`. The codes match the iOS bridge exactly, so the
// TypeScript layer maps one vocabulary. A reason, where there is one, rides in
// the code as "<CODE>:<Reason>", which Expo passes through unchanged (the
// message may be wrapped). The message also starts with the code in brackets,
// matching iOS, where the rejection reaches JS without a code.

private fun tagged(code: String, message: String) = "[$code] $message"

internal class ScaCancelledException :
    CodedException("SCA_CANCELLED", tagged("SCA_CANCELLED", "The ceremony was cancelled"), null)

internal class ScaFailedException(
    code: String,
    message: String,
) : CodedException(code, tagged(code, message), null)

internal class ScaInvalidConfigurationException(
    message: String,
) : CodedException("SCA_INVALID_CONFIGURATION", tagged("SCA_INVALID_CONFIGURATION", message), null)

internal class ScaCeremonyInProgressException :
    CodedException(
        "SCA_CEREMONY_IN_PROGRESS",
        tagged("SCA_CEREMONY_IN_PROGRESS", "Another SCA ceremony is still open"),
        null,
    )

internal fun mappedScaFailure(result: DaaScaResult.Failed): CodedException {
    val message = result.message ?: result.error.name
    return when (result.error) {
        DaaScaError.Expired -> ScaFailedException("SCA_EXPIRED", message)
        DaaScaError.Unsupported ->
            ScaFailedException("SCA_UNSUPPORTED:${result.unsupportedReason?.name ?: "PasskeyUnavailable"}", message)
        DaaScaError.AlreadyEnrolled -> ScaFailedException("SCA_ALREADY_ENROLLED", message)
        DaaScaError.Protocol -> ScaFailedException("SCA_PROTOCOL", message)
        DaaScaError.Transport -> ScaFailedException("SCA_TRANSPORT", message)
    }
}
