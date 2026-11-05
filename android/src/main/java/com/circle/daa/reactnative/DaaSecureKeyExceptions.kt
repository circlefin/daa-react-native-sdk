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

import com.circle.daa.sdk.DaaSecureKeyError
import com.circle.daa.sdk.DaaSecureKeyException
import expo.modules.kotlin.exception.CodedException

internal class UserAuthRequiredException :
    CodedException("USER_AUTH_REQUIRED", "User authentication is required", null)

internal class NotInitializedException :
    CodedException("NOT_INITIALIZED", "Secure key is not initialized", null)

internal class ContractViolationException(
    message: String = "Native secure-key operation failed",
) : CodedException("CONTRACT_VIOLATION", message, null)

internal fun mappedSecureKeyException(error: Throwable): CodedException {
    if (error is CodedException) {
        return error
    }
    val keyError =
        if (error is DaaSecureKeyException) {
            error.error
        } else {
            return ContractViolationException()
        }
    return when (keyError) {
        DaaSecureKeyError.UserCancelled,
        DaaSecureKeyError.AuthenticationFailed,
        DaaSecureKeyError.DeviceCredentialNotSet,
        -> UserAuthRequiredException()
        DaaSecureKeyError.KeyNotFound,
        DaaSecureKeyError.ResolutionRequired,
        -> NotInitializedException()
        DaaSecureKeyError.InvalidAppId,
        DaaSecureKeyError.InvalidSigningInput,
        DaaSecureKeyError.AuthKeyRegistrationRequired,
        DaaSecureKeyError.SecureHardwareUnavailable,
        DaaSecureKeyError.KeyCreationFailed,
        DaaSecureKeyError.KeyInvalidated,
        DaaSecureKeyError.KeyAccessFailed,
        DaaSecureKeyError.KeyMetadataUnavailable,
        DaaSecureKeyError.KeyMetadataVersionUnsupported,
        DaaSecureKeyError.ProtectionMismatch,
        DaaSecureKeyError.ProtectionUnavailable,
        DaaSecureKeyError.PublicKeyUnavailable,
        DaaSecureKeyError.SigningAlgorithmUnavailable,
        DaaSecureKeyError.SigningFailed,
        DaaSecureKeyError.SigningInputExpired,
        // Thrown when a registration device proof's header `jwk` is not the
        // signing key's own (its RFC 7638 thumbprint differs). An upstream
        // contract violation, not something to retry — the same mapping the
        // Swift bridge gives `authKeyThumbprintMismatch`.
        DaaSecureKeyError.AuthKeyThumbprintMismatch,
        -> ContractViolationException()
    }
}
