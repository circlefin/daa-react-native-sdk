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

import DaaSdk
import ExpoModulesCore
import Foundation

// Thin bridge over daa-ios-sdk's `DaaSca`. No ceremony logic lives here: the
// native SDK opens the hosted page, validates the callback and returns the
// page's response text, which is passed to JS unchanged (it is the exact
// X-Sca-Assertion value for approve, and the registration response JSON for
// enroll). The bridge only translates configuration and errors.

internal struct ScaConfigRecord: Record {
  @Field var environment: String = ""
  @Field var redirectUri: String = ""
  @Field var circleOrigin: String?
  @Field var approveTimeoutMs: Double?
  @Field var enrollTimeoutMs: Double?
}

public class DaaScaModule: Module {
  private let gate = ScaCeremonyGate()

  public func definition() -> ModuleDefinition {
    Name("DaaSca")

    AsyncFunction("capabilities") { (config: ScaConfigRecord) async throws -> [String: Any] in
      let configuration = try scaConfiguration(config)
      return await MainActor.run {
        let capabilities = DaaSca(configuration: configuration).capabilities()
        return [
          "protocolVersion": capabilities.protocolVersion,
          "surface": capabilities.surface == .webAuthenticationSession ? "webAuthenticationSession" : "none",
          "callbackReady": capabilities.callbackSupported,
          "platformPasskeys": capabilities.platformPasskeys,
          "ceremonySupported": capabilities.isCeremonySupported,
        ]
      }
    }

    AsyncFunction("approve") { (config: ScaConfigRecord, frameToken: String) async throws -> String in
      try await self.run(config) { sca in try await sca.approve(frameToken: frameToken) }
    }

    AsyncFunction("enroll") { (config: ScaConfigRecord, frameToken: String) async throws -> String in
      try await self.run(config) { sca in try await sca.enroll(frameToken: frameToken) }
    }
  }

  // One ceremony at a time across the whole app. The native SDK replaces an open
  // ceremony when a second starts on the same instance; the bridge refuses the
  // second call up front instead, so both platforms behave the same in JS.
  private func run(
    _ config: ScaConfigRecord,
    _ ceremony: @escaping @MainActor (DaaSca) async throws -> String
  ) async throws -> String {
    let configuration = try scaConfiguration(config)
    guard gate.enter() else {
      throw ScaCeremonyInProgressException()
    }
    defer { gate.leave() }
    do {
      return try await Task { @MainActor in
        try await ceremony(DaaSca(configuration: configuration))
      }.value
    } catch {
      throw mappedScaException(error)
    }
  }
}

private func scaConfiguration(_ config: ScaConfigRecord) throws -> DaaScaConfiguration {
  // Only the public environments; any other Circle host goes through
  // `circleOrigin`, which the native configuration validates.
  let environment: DaaEnvironment
  switch config.environment {
  case "sandbox": environment = .sandbox
  case "production": environment = .production
  default: throw ScaInvalidConfigurationException("environment must be 'sandbox' or 'production'")
  }
  do {
    return try DaaScaConfiguration(
      environment: environment,
      redirectURI: config.redirectUri,
      circleOrigin: config.circleOrigin,
      approveTimeout: (config.approveTimeoutMs.map { $0 / 1000 }) ?? DaaScaConfiguration.defaultApproveTimeout,
      enrollTimeout: (config.enrollTimeoutMs.map { $0 / 1000 }) ?? DaaScaConfiguration.defaultEnrollTimeout
    )
  } catch let error as DaaScaConfigurationError {
    throw ScaInvalidConfigurationException(String(describing: error))
  }
}

private final class ScaCeremonyGate: @unchecked Sendable {
  private let lock = NSLock()
  private var open = false

  func enter() -> Bool {
    lock.lock()
    defer { lock.unlock() }
    guard !open else { return false }
    open = true
    return true
  }

  func leave() {
    lock.lock()
    open = false
    lock.unlock()
  }
}
