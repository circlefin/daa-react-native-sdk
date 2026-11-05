# Copyright (c) 2026, Circle Internet Group, Inc. All rights reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require 'json'

package = JSON.parse(File.read(File.join(__dir__, 'package.json')))

Pod::Spec.new do |s|
  s.name           = 'DaaReactNativeSdk'
  s.version        = package['version']
  s.summary        = package['description']
  s.description    = package['description']
  s.license        = package['license']
  s.author         = package['author']
  s.homepage       = package['homepage']
  s.platforms      = { :ios => '15.0' }
  s.swift_version  = '5.9'
  s.source         = { :git => 'https://github.com/circlefin/daa-react-native-sdk.git', :tag => "v#{s.version}" }
  s.static_framework = true

  s.dependency 'ExpoModulesCore'

  # Expo module sources only. DaaSdk is the native iOS SDK (daa-ios-sdk),
  # consumed as a published CocoaPods dependency rather than vendored at pack
  # time. Integrators add the daa-ios-sdk spec-source repo to their Podfile
  # `source` — see README.md.
  # Pin the native SDK so dependency resolution is reproducible and updates are
  # deliberate. 0.7.1 provides the APIs and behaviour this module relies on:
  # it sets all of the Face ID / Touch ID prompt text itself from the validated
  # operation, so signDeviceAuthorization and signRegistrationDeviceAuthorization
  # take no caller prompt and DaaSecureKeyModule.swift passes none; it defaults
  # the AuthKey Keychain group to the app's own application-identifier group
  # (this module passes no keychainAccessGroup) and fails closed if that group
  # cannot be resolved; its registration signer accepts the minimal
  # device-proof claim set this package sends; it has the native SCA ceremony
  # (`DaaSca`), which DaaScaModule.swift bridges and which also needs
  # AuthenticationServices below; and it has DaaPrepareReceiptSignature,
  # DaaSecureRandom, DaaRegistrationFlowKey, and
  # DaaRegistrationFlowKeyError.invalidSigningInput, which
  # DaaRegistrationModule.swift and DaaRegistrationExceptions.swift use.
  s.source_files = 'ios/*.{h,m,mm,swift}'
  s.dependency 'DaaSdk', '0.7.1'
  s.frameworks = 'Security', 'LocalAuthentication', 'CryptoKit', 'AuthenticationServices'

  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
    'SWIFT_COMPILATION_MODE' => 'wholemodule',
    'OTHER_SWIFT_FLAGS' => '$(inherited) -enable-upcoming-feature StrictConcurrency'
  }
end
