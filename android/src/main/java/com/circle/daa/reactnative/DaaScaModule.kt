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

import androidx.activity.result.contract.ActivityResultContract
import com.circle.daa.sdk.DaaEnvironment
import com.circle.daa.sdk.sca.DaaSca
import com.circle.daa.sdk.sca.DaaScaApproveContract
import com.circle.daa.sdk.sca.DaaScaConfig
import com.circle.daa.sdk.sca.DaaScaEnrollContract
import com.circle.daa.sdk.sca.DaaScaResult
import expo.modules.kotlin.Promise
import expo.modules.kotlin.functions.Queues
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import expo.modules.kotlin.records.Field
import expo.modules.kotlin.records.Record

// Thin bridge over daa-android-sdk's SCA contracts. No ceremony logic lives here:
// the native SDK opens the hosted page, validates the callback and returns the
// page's response text, which is passed to JS unchanged (the exact
// X-Sca-Assertion value for approve, the registration response JSON for enroll).
// The bridge only translates configuration, the activity result and errors.

internal class ScaConfigRecord : Record {
    @Field val environment: String = ""

    @Field val redirectUri: String = ""

    @Field val circleOrigin: String? = null

    @Field val approveTimeoutMs: Double? = null

    @Field val enrollTimeoutMs: Double? = null
}

class DaaScaModule : Module() {
    private class Pending(
        val contract: ActivityResultContract<String, DaaScaResult>,
        val promise: Promise,
    )

    // One ceremony at a time across the whole app. The native SDK ends an open
    // ceremony when a second launch arrives; the bridge refuses the second call up
    // front instead, so both platforms behave the same in JS. Main thread only.
    private var pending: Pending? = null

    override fun definition() =
        ModuleDefinition {
            Name("DaaSca")

            AsyncFunction("capabilities") { config: ScaConfigRecord ->
                val context = appContext.reactContext ?: throw ScaInvalidConfigurationException("No React context")
                val capabilities = DaaSca.capabilities(context, scaConfig(config))
                mapOf(
                    "protocolVersion" to capabilities.protocolVersion,
                    "surface" to capabilities.surface.name.replaceFirstChar { it.lowercase() },
                    "callbackReady" to capabilities.callbackRegistered,
                    "callbackVerified" to capabilities.callbackVerified,
                    "callbackTaskIsolated" to capabilities.callbackTaskIsolated,
                    "platformPasskeys" to capabilities.platformPasskeys,
                )
            }

            AsyncFunction("approve") { config: ScaConfigRecord, frameToken: String, promise: Promise ->
                launch(promise, frameToken) { DaaScaApproveContract(scaConfig(config)) }
            }.runOnQueue(Queues.MAIN)

            AsyncFunction("enroll") { config: ScaConfigRecord, frameToken: String, promise: Promise ->
                launch(promise, frameToken) { DaaScaEnrollContract(scaConfig(config)) }
            }.runOnQueue(Queues.MAIN)

            OnActivityResult { _, payload ->
                if (payload.requestCode != REQUEST_CODE) return@OnActivityResult
                val current = pending ?: return@OnActivityResult
                pending = null
                settle(current.promise, current.contract.parseResult(payload.resultCode, payload.data))
            }
        }

    private fun launch(
        promise: Promise,
        frameToken: String,
        contract: () -> ActivityResultContract<String, DaaScaResult>,
    ) {
        if (pending != null) {
            promise.reject(ScaCeremonyInProgressException())
            return
        }
        val built =
            try {
                contract()
            } catch (error: IllegalArgumentException) {
                // A custom-scheme redirect URI for approve, or an invalid config.
                promise.reject(ScaInvalidConfigurationException(error.message ?: "Invalid SCA configuration"))
                return
            } catch (error: ScaInvalidConfigurationException) {
                promise.reject(error)
                return
            }
        val activity = appContext.currentActivity
        if (activity == null) {
            promise.reject(ScaFailedException("SCA_UNSUPPORTED:SessionUnavailable", "No foreground activity"))
            return
        }
        // Building the intent validates the frame token (blank or too long): a caller
        // bug, reported like iOS, never as "unsupported".
        val intent =
            try {
                built.createIntent(activity, frameToken)
            } catch (error: IllegalArgumentException) {
                val detail = error.message ?: "frameToken is invalid"
                promise.reject(ScaFailedException("SCA_PROTOCOL:InvalidFrameToken", detail))
                return
            }
        pending = Pending(built, promise)
        try {
            activity.startActivityForResult(intent, REQUEST_CODE)
        } catch (error: RuntimeException) {
            // OnActivityResult never fires for a ceremony that did not start, so the
            // slot must be released here or every later call would be refused.
            pending = null
            val detail = error.message ?: "the ceremony could not start"
            promise.reject(ScaFailedException("SCA_UNSUPPORTED:SessionUnavailable", detail))
        }
    }

    private fun settle(
        promise: Promise,
        result: DaaScaResult,
    ) {
        when (result) {
            is DaaScaResult.Completed -> promise.resolve(result.response)
            is DaaScaResult.Cancelled -> promise.reject(ScaCancelledException())
            is DaaScaResult.Failed -> promise.reject(mappedScaFailure(result))
        }
    }

    private companion object {
        // Distinct from any request code the host app is likely to use.
        const val REQUEST_CODE = 0x5CA1
    }
}

private fun scaConfig(config: ScaConfigRecord): DaaScaConfig {
    // Only the public environments; any other Circle host goes through
    // `circleOrigin`, which the native configuration validates.
    val environment =
        when (config.environment) {
            "sandbox" -> DaaEnvironment.Sandbox
            "production" -> DaaEnvironment.Production
            else -> throw ScaInvalidConfigurationException("environment must be 'sandbox' or 'production'")
        }
    return try {
        DaaScaConfig(
            environment = environment,
            redirectUri = config.redirectUri,
            circleOrigin = config.circleOrigin,
            approveTimeoutMillis = config.approveTimeoutMs?.toLong() ?: DaaScaConfig.DEFAULT_APPROVE_TIMEOUT_MILLIS,
            enrollTimeoutMillis = config.enrollTimeoutMs?.toLong() ?: DaaScaConfig.DEFAULT_ENROLL_TIMEOUT_MILLIS,
        )
    } catch (error: IllegalArgumentException) {
        throw ScaInvalidConfigurationException(error.message ?: "Invalid SCA configuration")
    }
}
