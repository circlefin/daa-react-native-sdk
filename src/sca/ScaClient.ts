/**
 * Copyright (c) 2026, Circle Internet Group, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { requireOptionalNativeModule } from 'expo-modules-core'

/**
 * Passkey strong customer authentication (SCA) through Circle's hosted
 * ceremony page, run by the native iOS / Android SDKs.
 *
 * The flow: your backend opens a challenge (or registration) with your app's
 * `redirectUri` and keeps the returned id; it hands the app only the
 * `frameToken`. The app calls {@link ScaClient.approve} (or `enroll`) and sends
 * the returned string, unmodified, back to the backend, which retries the
 * gated request with `X-Sca-Challenge-Id` and `X-Sca-Assertion`.
 */

/** Public environments only; reach another Circle host with `circleOrigin`. */
export type ScaEnvironment = 'sandbox' | 'production'

export interface ScaConfig {
  environment: ScaEnvironment
  /**
   * The callback URI registered with Circle for your app, exactly as
   * registered. Android requires an `https` App Link for `approve`.
   */
  redirectUri: string
  /**
   * Another Circle ceremony origin (bare `https://*.circle.com`). Only with
   * `sandbox`; refused for `production`.
   */
  circleOrigin?: string
  /** Deadline for an approval, ms. Default 300 000, range 30 000–3 600 000. */
  approveTimeoutMs?: number
  /** Deadline for an enrollment, ms. Default 600 000, range 30 000–3 600 000. */
  enrollTimeoutMs?: number
}

export type ScaErrorCode =
  | 'Cancelled'
  | 'Expired'
  | 'Unsupported'
  | 'AlreadyEnrolled'
  | 'Protocol'
  | 'Transport'
  | 'InvalidConfiguration'
  | 'CeremonyInProgress'
  | 'NativeModuleUnavailable'

/**
 * A failed ceremony. `code` is the stable vocabulary to branch on; `reason`
 * narrows `Unsupported` and `Protocol` where the platform can tell (for
 * example `NoAllowedBrowser`, `CallbackNotRouted`, `SessionUnavailable`,
 * `StateMismatch`, `InvalidFrameToken`). `Protocol` is an integration bug,
 * never a reason to offer a different authentication method.
 *
 * The SDK always sets `message` to one of its own literals, never to text from
 * the native SDKs: it is what crash reporters log by default. For a failure that
 * came from native, the native rejection is kept as `cause` for deliberate
 * inspection.
 */
export class ScaError extends Error {
  readonly code: ScaErrorCode
  readonly reason: string | null
  // The native rejection this error was mapped from, if any. Kept off
  // `message` (so it never lands in logs by default) but available to a host
  // that deliberately inspects `err.cause`.
  readonly cause: unknown

  constructor(
    code: ScaErrorCode,
    message: string,
    reason: string | null = null,
    cause: unknown = undefined,
  ) {
    super(message)
    this.name = 'ScaError'
    this.code = code
    this.reason = reason
    this.cause = cause
    // Keep `cause` non-enumerable so JSON.stringify and crash reporters that
    // walk own enumerable properties do not export the native rejection (its
    // message, code, or native stack). It stays readable via `err.cause`.
    Object.defineProperty(this, 'cause', { enumerable: false })
  }
}

export function isScaError(err: unknown): err is ScaError {
  return err instanceof ScaError
}

export interface ScaCapabilities {
  protocolVersion: number
  /** `webAuthenticationSession` (iOS), `authTab` / `customTab` (Android), or `none`. */
  surface: string
  /** The redirect URI reaches this app's callback (Android: an exported, routed activity). */
  callbackReady: boolean
  /** Android API 31+: whether the App Link is verified; otherwise `null`. */
  callbackVerified: boolean | null
  /** Android: whether the callback activity is task-isolated; otherwise `null`. */
  callbackTaskIsolated: boolean | null
  platformPasskeys: boolean
}

export interface ScaClient {
  readonly config: Readonly<ScaConfig>
  /** Returns the exact `X-Sca-Assertion` value. Send it unmodified. */
  approve(frameToken: string): Promise<string>
  /** Returns the registration response JSON text for your backend. */
  enroll(frameToken: string): Promise<string>
  capabilities(): Promise<ScaCapabilities>
}

interface DaaScaNativeModule {
  approve(config: ScaConfig, frameToken: string): Promise<string>
  enroll(config: ScaConfig, frameToken: string): Promise<string>
  capabilities(config: ScaConfig): Promise<Record<string, unknown>>
}

const NATIVE_CODES: Readonly<Record<string, ScaErrorCode>> = {
  SCA_CANCELLED: 'Cancelled',
  SCA_EXPIRED: 'Expired',
  SCA_UNSUPPORTED: 'Unsupported',
  SCA_ALREADY_ENROLLED: 'AlreadyEnrolled',
  SCA_PROTOCOL: 'Protocol',
  SCA_TRANSPORT: 'Transport',
  SCA_INVALID_CONFIGURATION: 'InvalidConfiguration',
  SCA_CEREMONY_IN_PROGRESS: 'CeremonyInProgress',
}

// The `message` for each code. The native rejection's own text never reaches
// `ScaError.message`: it can carry platform or internal detail, and `message`
// is what crash reporters log by default. The native rejection stays on the
// non-enumerable `cause`.
const MESSAGES: Readonly<Record<ScaErrorCode, string>> = {
  Cancelled: 'The SCA ceremony was cancelled',
  Expired: 'The SCA ceremony deadline passed',
  Unsupported: 'This device or app cannot run the SCA ceremony',
  AlreadyEnrolled: 'A passkey is already enrolled on this authenticator',
  Protocol: 'The SCA ceremony failed with a protocol error',
  Transport: 'The SCA ceremony failed on a transport error',
  InvalidConfiguration: 'The SCA configuration was rejected',
  CeremonyInProgress: 'Another SCA ceremony is still open',
  NativeModuleUnavailable: 'The DaaSca native module is not linked in this build',
}

// Expo prefixes an async function's message ("Calling the 'approve' function
// has failed\n→ Caused by: …"), so the tag is read from the innermost cause.
// Android passes the native exception's code through; iOS does not (the
// rejection reaches JS without a code), so both bridges also tag the innermost
// message with the code ("[SCA_UNSUPPORTED:NoAllowedBrowser] …"). A known
// `code` wins; otherwise the tag is used; otherwise it is a Protocol failure.
// The message itself is read only for that tag.
const CAUSE_SEPARATOR = '→ Caused by: '
const CODE_TAG = /^\[(SCA_[A-Z_]+(?::[A-Za-z]+)?)\] ?/
// A reason is a name from the platform's vocabulary. One with any other shape
// is native text, not a reason, and is dropped rather than passed on.
const REASON = /^[A-Za-z]+$/

function innermostMessage(message: string): string {
  const at = message.lastIndexOf(CAUSE_SEPARATOR)
  return at < 0 ? message : message.slice(at + CAUSE_SEPARATOR.length)
}

function knownCode(base: string): ScaErrorCode | undefined {
  return Object.prototype.hasOwnProperty.call(NATIVE_CODES, base) ? NATIVE_CODES[base] : undefined
}

function splitCode(nativeCode: string): [string, string | null] {
  const separator = nativeCode.indexOf(':')
  if (separator < 0) {
    return [nativeCode, null]
  }
  const reason = nativeCode.slice(separator + 1)
  return [nativeCode.slice(0, separator), REASON.test(reason) ? reason : null]
}

/**
 * Translates a native rejection into a {@link ScaError}. The result's
 * `message` is the fixed text for its code; the rejection itself is kept as
 * the non-enumerable `cause`.
 */
export function mapNativeScaError(err: unknown): ScaError {
  if (err instanceof ScaError) {
    return err
  }
  const rawCode =
    typeof (err as { code?: unknown })?.code === 'string' ? (err as { code: string }).code : ''
  const rawMessage =
    typeof (err as { message?: unknown })?.message === 'string'
      ? (err as { message: string }).message
      : ''
  const tag = CODE_TAG.exec(innermostMessage(rawMessage))
  const fromCode = splitCode(rawCode)
  const [base, reason] = knownCode(fromCode[0])
    ? fromCode
    : tag
      ? splitCode(tag[1] ?? '')
      : fromCode
  const code = knownCode(base) ?? 'Protocol'
  return new ScaError(code, MESSAGES[code], reason, err)
}

function validated(config: ScaConfig): Readonly<ScaConfig> {
  if (config.environment !== 'sandbox' && config.environment !== 'production') {
    throw new ScaError('InvalidConfiguration', "environment must be 'sandbox' or 'production'")
  }
  if (typeof config.redirectUri !== 'string' || config.redirectUri.length === 0) {
    throw new ScaError('InvalidConfiguration', 'redirectUri is required')
  }
  // The native SDKs re-validate everything (URI rules, origin, timeout range).
  return Object.freeze({ ...config })
}

/**
 * Creates an SCA client. One ceremony runs at a time across the app: a second
 * `approve` or `enroll` while one is open rejects with `CeremonyInProgress`
 * and leaves the open one alone. Disable the control that starts a ceremony
 * until the call settles.
 */
export function createScaClient(
  config: ScaConfig,
  native: DaaScaNativeModule | null = requireOptionalNativeModule<DaaScaNativeModule>('DaaSca'),
): ScaClient {
  const frozen = validated(config)
  const module = (): DaaScaNativeModule => {
    if (native === null) {
      throw new ScaError('NativeModuleUnavailable', MESSAGES.NativeModuleUnavailable)
    }
    return native
  }
  let inFlight = false

  const ceremony = async (
    run: (n: DaaScaNativeModule) => Promise<string>,
    frameToken: string,
  ): Promise<string> => {
    if (typeof frameToken !== 'string' || frameToken.length === 0) {
      throw new ScaError('InvalidConfiguration', 'frameToken is required')
    }
    if (inFlight) {
      throw new ScaError('CeremonyInProgress', MESSAGES.CeremonyInProgress)
    }
    inFlight = true
    try {
      return await run(module())
    } catch (err) {
      throw mapNativeScaError(err)
    } finally {
      inFlight = false
    }
  }

  return {
    config: frozen,
    approve: (frameToken) => ceremony((n) => n.approve(frozen, frameToken), frameToken),
    enroll: (frameToken) => ceremony((n) => n.enroll(frozen, frameToken), frameToken),
    async capabilities() {
      try {
        const raw = await module().capabilities(frozen)
        return {
          protocolVersion: Number(raw.protocolVersion),
          surface: String(raw.surface),
          callbackReady: raw.callbackReady === true,
          callbackVerified: typeof raw.callbackVerified === 'boolean' ? raw.callbackVerified : null,
          callbackTaskIsolated:
            typeof raw.callbackTaskIsolated === 'boolean' ? raw.callbackTaskIsolated : null,
          platformPasskeys: raw.platformPasskeys === true,
        }
      } catch (err) {
        throw mapNativeScaError(err)
      }
    },
  }
}
