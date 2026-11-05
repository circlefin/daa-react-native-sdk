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

import type { DaaTransport } from './transport/DaaTransport'

/**
 * Environment namespaces keys, credentials, and endpoints. The public
 * environments are `sandbox` (testnet) and `production` (mainnet). With
 * `sandbox`, `publicApiOrigin` overrides the API origin with another bare https
 * origin on circle.com or a subdomain.
 *
 * Exposed as a runtime allow-list so a JS caller passing an unknown value (which
 * the compile-time type cannot catch) fails fast instead of silently creating a
 * separate key namespace.
 */
export const DAA_ENVIRONMENTS = ['sandbox', 'production'] as const

export type DaaEnvironment = (typeof DAA_ENVIRONMENTS)[number]

const PUBLIC_API_ORIGINS: Readonly<Record<DaaEnvironment, string>> = Object.freeze({
  sandbox: 'https://api-sandbox.circle.com',
  production: 'https://api.circle.com',
})

const CIRCLE_DOMAIN = 'circle.com'

/**
 * The closed DeviceKeyPolicy. Application code cannot request an exportable
 * private key or bypass required local authentication. The only accepted value
 * is this singleton.
 */
export const DEVICE_KEY_POLICY = Object.freeze({
  hardwareBacked: true,
  userVerification: 'REQUIRED_FOR_EACH_SIGNATURE',
} as const)

export type DeviceKeyPolicy = typeof DEVICE_KEY_POLICY

export function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object'
}

/** True when `value` matches the closed DeviceKeyPolicy exactly. */
export function isRequiredDeviceKeyPolicy(value: unknown): value is DeviceKeyPolicy {
  return (
    isRecord(value) &&
    value['hardwareBacked'] === DEVICE_KEY_POLICY.hardwareBacked &&
    value['userVerification'] === DEVICE_KEY_POLICY.userVerification
  )
}

/**
 * Runtime allow-list for `keyPolicy`. TypeScript cannot catch a JS caller
 * passing a weaker object, so construction fail-closes unless the value
 * matches `DEVICE_KEY_POLICY`. Returns the canonical frozen singleton so extra
 * fields on the caller's object cannot leak into stored config.
 */
export function assertDeviceKeyPolicy(value: unknown): DeviceKeyPolicy {
  if (value === undefined || value === null) {
    throw new Error('DAA: keyPolicy is required')
  }
  if (!isRequiredDeviceKeyPolicy(value)) {
    throw new Error(
      'DAA: keyPolicy must be hardware-backed with REQUIRED_FOR_EACH_SIGNATURE user verification',
    )
  }
  return DEVICE_KEY_POLICY
}

export type DaaSdkConfiguration = Readonly<{
  /**
   * Identifies the application integration and namespaces local key storage:
   * `[A-Za-z0-9._-]`, at most 41 characters. `DaaClient` refuses any other value.
   */
  appId: string
  environment: DaaEnvironment
  /** Required. The SDK never embeds a DAA service credential. */
  transport: DaaTransport
  /** Closed set; must be `DEVICE_KEY_POLICY`. */
  keyPolicy: DeviceKeyPolicy
  /**
   * Overrides the sandbox API origin with another bare, lowercase https origin
   * on circle.com or a subdomain. Only with `sandbox`; refused for
   * `production`. Replaces the environment's origin as the pagination trust
   * anchor.
   */
  publicApiOrigin?: string
}>

/** SDK-owned trust anchor used to authenticate absolute pagination links. */
export function publicApiOriginFor(environment: DaaEnvironment): string {
  return PUBLIC_API_ORIGINS[environment]
}

/**
 * Validates `publicApiOrigin` against `environment`, with the rule the native
 * SDKs apply to the SCA `circleOrigin` override. Production is refused first,
 * so an override left in a debug configuration fails at construction instead
 * of trusting another origin for production pagination. Returns the override,
 * or `undefined` when none is set.
 */
export function assertPublicApiOrigin(
  environment: DaaEnvironment,
  publicApiOrigin: unknown,
): string | undefined {
  if (publicApiOrigin === undefined) {
    return undefined
  }
  if (environment === 'production') {
    throw new Error('DAA: publicApiOrigin cannot be set for production')
  }
  if (typeof publicApiOrigin !== 'string' || !isCircleOrigin(publicApiOrigin)) {
    throw new Error(
      'DAA: publicApiOrigin must be a bare, lowercase https origin on circle.com or a subdomain',
    )
  }
  return publicApiOrigin
}

/**
 * A bare, lowercase `https://<host>` origin on `circle.com` or one of its
 * subdomains: no port, path, query, fragment, or credentials. Anything that
 * would need normalizing is refused rather than normalized.
 */
function isCircleOrigin(origin: string): boolean {
  const prefix = 'https://'
  if (!origin.startsWith(prefix)) {
    return false
  }
  const host = origin.slice(prefix.length)
  return (
    (host === CIRCLE_DOMAIN || host.endsWith(`.${CIRCLE_DOMAIN}`)) &&
    host.length <= 253 &&
    host.split('.').every(isDnsLabel)
  )
}

/** A lowercase LDH label: 1–63 of `[a-z0-9-]`, not starting or ending with a hyphen. */
function isDnsLabel(label: string): boolean {
  return /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)
}
