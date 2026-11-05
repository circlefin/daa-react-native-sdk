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

import android.content.Context
import androidx.fragment.app.FragmentActivity
import com.circle.daa.sdk.DaaAuthKeyIdentity
import com.circle.daa.sdk.DaaAuthKeyResolution
import com.circle.daa.sdk.DaaDeviceAuthorizationSigningInput
import com.circle.daa.sdk.DaaEnvironment
import com.circle.daa.sdk.DaaRegistrationAuthorizationSigningInput
import com.circle.daa.sdk.DaaSecureKey
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.runBlocking

class DaaSecureKeyModule : Module() {
    private val keys = ConcurrentHashMap<String, DaaSecureKey>()
    private val installationLock = Any()

    @Volatile
    private var installationId: UUID? = null

    override fun definition() = ModuleDefinition {
        Name("DaaSecureKey")

        // Mirrors `DEVICE_KEY_POLICY` in src/config.ts. This is a compiled-in
        // constant, not a live readback of a specific key's real Keystore
        // protection: it is a version-skew guard between this module and the
        // TypeScript it ships with, so a mismatch means the two disagree
        // about the closed set, not that a key was inspected and found
        // wanting. daa-android-sdk's public `SecureKey` does not expose the
        // key's `KeyInfo`, so this module has no per-key protection to read
        // back.
        Function("declaredKeyPolicy") {
            mapOf(
                "hardwareBacked" to true,
                "userVerification" to "REQUIRED_FOR_EACH_SIGNATURE",
            )
        }

        AsyncFunction("resolveOrCreate") { appId: String, environment: String ->
            runKey {
                when (keyFor(appId, environment).resolveOrCreate()) {
                    DaaAuthKeyResolution.Created -> "created"
                    DaaAuthKeyResolution.Existing -> "existing"
                }
            }
        }

        AsyncFunction("publicKeySpkiBase64Url") { appId: String, environment: String ->
            runKey { keyFor(appId, environment).publicKeySpkiBase64Url() }
        }

        // Reached from OwnerAuthKey.acknowledgeRegistration() via the TS bridge.
        // This is the only registration-ack entry point; do not add a parallel one.
        AsyncFunction("acknowledgeRegistration") { appId: String, environment: String ->
            runKey { keyFor(appId, environment).acknowledgeRegistration() }
        }

        // Typed native signDeviceAuthorization — not a generic sign(bytes). The
        // Base64URL payload is the exact compact-JWS signing input already built
        // in TypeScript; native validates those bytes and signs that same slice.
        // There is no prompt argument: daa-android-sdk sets all of the
        // BiometricPrompt text from the validated operation and shows it over
        // the current FragmentActivity; nothing here can change that text.
        AsyncFunction("signDeviceAuthorization") {
                appId: String,
                environment: String,
                signingInputBase64Url: String,
            ->
            val activity =
                appContext.currentActivity as? FragmentActivity
                    ?: throw ContractViolationException(
                        "signDeviceAuthorization requires a FragmentActivity",
                    )
            runKey {
                val signature =
                    keyFor(appId, environment).signDeviceAuthorization(
                        DaaDeviceAuthorizationSigningInput(
                            decodeUnpaddedBase64Url(signingInputBase64Url),
                        ),
                        activity,
                    )
                unpaddedBase64Url(signature)
            }
        }

        // Typed native signRegistrationDeviceAuthorization — the registration
        // counterpart of signDeviceAuthorization above, NOT the same call. The
        // Base64URL payload is the exact Device Registration Complete
        // device-proof signing input from `auth/registrationAuthorization.ts`;
        // it is validated by DaaRegistrationAuthorizationSigningInput, a
        // different validator from DaaDeviceAuthorizationSigningInput
        // (registration `typ`s, an embedded JWK header, no acknowledged-key
        // gate). Do not route this input through signDeviceAuthorization
        // above, and do not route that input through here. Like
        // signDeviceAuthorization, it takes no prompt: daa-android-sdk shows
        // its own device-registration prompt text.
        AsyncFunction("signRegistrationDeviceAuthorization") {
                appId: String,
                environment: String,
                signingInputBase64Url: String,
            ->
            val activity =
                appContext.currentActivity as? FragmentActivity
                    ?: throw ContractViolationException(
                        "signRegistrationDeviceAuthorization requires a FragmentActivity",
                    )
            runKey {
                val signature =
                    keyFor(appId, environment).signRegistrationDeviceAuthorization(
                        DaaRegistrationAuthorizationSigningInput(
                            decodeUnpaddedBase64Url(signingInputBase64Url),
                        ),
                        activity,
                    )
                unpaddedBase64Url(signature)
            }
        }
    }

    private fun <T> runKey(block: suspend () -> T): T {
        return try {
            runBlocking { block() }
        } catch (error: Throwable) {
            throw mappedSecureKeyException(error)
        }
    }

    private fun keyFor(appId: String, environmentWire: String): DaaSecureKey {
        val environment =
            DaaEnvironment.entries.find { it.wireValue == environmentWire }
                ?: throw ContractViolationException()
        val alias = "$appId.${environment.wireValue}"
        val existing = keys[alias]
        if (existing != null) {
            return existing
        }
        val context =
            appContext.reactContext?.applicationContext
                ?: throw ContractViolationException()
        val identity =
            DaaAuthKeyIdentity(
                appId = appId,
                environment = environment,
                installationId = installationId(context),
            )
        val created = DaaSecureKey(context, identity)
        val raced = keys.putIfAbsent(alias, created)
        return raced ?: created
    }

    private fun installationId(context: Context): UUID {
        val cached = installationId
        if (cached != null) {
            return cached
        }
        synchronized(installationLock) {
            val locked = installationId
            if (locked != null) {
                return locked
            }
            val loaded = InstallationIdentityStore.loadOrCreate(context)
            installationId = loaded
            return loaded
        }
    }
}
