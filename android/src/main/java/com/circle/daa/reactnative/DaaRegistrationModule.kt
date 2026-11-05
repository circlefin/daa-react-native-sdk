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

import com.circle.daa.sdk.DaaPrepareReceiptSignature
import com.circle.daa.sdk.DaaRegistrationAuthorizationSigningInput
import com.circle.daa.sdk.DaaRegistrationFlowKey
import com.circle.daa.sdk.DaaSecureRandom
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

// Thin Expo bridge to the native registration primitives. THIS IS NOT
// DaaSecureKey. Verifier bytes come from DaaSecureRandom; the ephemeral
// flow key is DaaRegistrationFlowKey, cached here so the private key never
// crosses into JavaScript; the Prepare receipt signature is checked by
// DaaPrepareReceiptSignature.

class DaaRegistrationModule : Module() {
    private val flowKeys = ConcurrentHashMap<String, DaaRegistrationFlowKey>()

    override fun definition() =
        ModuleDefinition {
            Name("DaaRegistration")

            Function("randomBytes") { count: Int ->
                runRegistration { unpaddedBase64Url(DaaSecureRandom.bytes(count)) }
            }

            Function("randomUuidV4") {
                UUID.randomUUID().toString()
            }

            Function("generateRegistrationFlowKey") {
                runRegistration {
                    val key = DaaRegistrationFlowKey.generate()
                    val id = UUID.randomUUID().toString()
                    flowKeys[id] = key
                    id
                }
            }

            Function("registrationFlowPublicKeySpkiBase64Url") { id: String ->
                runRegistration {
                    val key =
                        flowKeys[id]
                            ?: throw RegistrationContractViolationException()
                    key.publicKeySpkiBase64Url()
                }
            }

            // Drops the cached key so its private half is no longer reachable and
            // becomes collectable. Without this the map grows by one P-256 private
            // key per login attempt and never shrinks, which contradicts the point
            // of generating the key natively: shortening how long key material is
            // resident. Idempotent, and deliberately silent about an unknown id —
            // release is cleanup, and a caller releasing twice (or in a `finally`
            // after a failure) must not turn tidying up into an error.
            Function("releaseRegistrationFlowKey") { id: String ->
                flowKeys.remove(id)
                Unit
            }

            // Typed native signRegistrationAuthorization — not a generic
            // sign(bytes). The Base64URL payload is the exact Device
            // Registration Complete flow-JWS signing input already built in
            // TypeScript; native validates those bytes and signs that same
            // slice. Synchronous and prompt-free: the flow key is in process
            // memory, not the Keystore, so there is no biometric gate.
            Function("signRegistrationAuthorization") { id: String, signingInputBase64Url: String ->
                runRegistration {
                    val key = flowKeys[id] ?: throw RegistrationContractViolationException()
                    val signature =
                        key.signRegistrationAuthorization(
                            DaaRegistrationAuthorizationSigningInput(
                                decodeUnpaddedBase64Url(signingInputBase64Url),
                            ),
                        )
                    unpaddedBase64Url(signature)
                }
            }

            // Verify-only, against a key JS pinned from the SDK's own trust
            // anchor — never a key from the token. DaaPrepareReceiptSignature
            // (daa-android-sdk) does the check with java.security: a signature
            // problem is `false`, and a key that is not a P-256 point throws
            // and maps to CONTRACT_VIOLATION.
            AsyncFunction("verifyPrepareReceiptSignature") { publicKeyX963Base64Url: String, signingInputBase64Url: String, signatureBase64Url: String ->
                runRegistration {
                    DaaPrepareReceiptSignature.verify(
                        decodeUnpaddedBase64Url(publicKeyX963Base64Url),
                        decodeUnpaddedBase64Url(signingInputBase64Url),
                        decodeUnpaddedBase64Url(signatureBase64Url),
                    )
                }
            }
        }

    private fun <T> runRegistration(block: () -> T): T {
        return try {
            block()
        } catch (error: Throwable) {
            throw mappedRegistrationException(error)
        }
    }
}
