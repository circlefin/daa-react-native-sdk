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

import Foundation

// Durable per-install UUID for DaaAuthKeyIdentity.installationID.
// Native docs: the caller persists the UUID; a new install gets a new UUID.
//
// Stored as a file in the app container's Application Support directory,
// excluded from backup. The container survives app updates and is deleted
// when the app is deleted, so a reinstall mints a new UUID and therefore a
// new Enclave AuthKey — the same lifetime Android gets from noBackupFilesDir.
// Excluding it from backup keeps a restore onto another device (or the same
// device after an erase) from carrying the UUID over. UserDefaults is not
// used because it is always included in backups. The Keychain is not used
// because iOS does not reliably purge it when the app is deleted.
//
// Keys minted under an earlier installation UUID stay in this app's Keychain
// access group: they are unreachable from this store, and they are not
// deleted here or revoked at Circle.

enum InstallationIdentityStoreError: Error, Equatable {
  case applicationSupportUnavailable
  case unreadable
  case unwritable
}

struct InstallationIdentityStore {
  static let fileName = "installation-id.v1"
  private static let directoryName = "com.circle.daa.reactnative"
  // Process-wide: concurrent first runs must not each write a different UUID.
  private static let lock = NSLock()

  let directory: URL

  static func live() throws -> InstallationIdentityStore {
    guard let applicationSupport = try? FileManager.default.url(
      for: .applicationSupportDirectory,
      in: .userDomainMask,
      appropriateFor: nil,
      create: true
    ) else {
      throw InstallationIdentityStoreError.applicationSupportUnavailable
    }
    return InstallationIdentityStore(
      directory: applicationSupport.appendingPathComponent(directoryName, isDirectory: true)
    )
  }

  func loadOrCreate() throws -> UUID {
    Self.lock.lock()
    defer { Self.lock.unlock() }

    let file = directory.appendingPathComponent(Self.fileName, isDirectory: false)
    if let existing = try read(file) {
      return existing
    }
    let id = UUID()
    try write(id, to: file)
    return id
  }

  private func read(_ file: URL) throws -> UUID? {
    guard FileManager.default.fileExists(atPath: file.path) else {
      return nil
    }
    let data: Data
    do {
      data = try Data(contentsOf: file)
    } catch {
      // Present but unreadable (for example before the first unlock after
      // boot): fail and let the next call retry. Never remint over it.
      throw InstallationIdentityStoreError.unreadable
    }
    guard let string = String(data: data, encoding: .utf8),
          let id = UUID(uuidString: string.trimmingCharacters(in: .whitespacesAndNewlines))
    else {
      // Malformed file: delete and remint. The previous Enclave key is not
      // deleted and is not revoked at Circle. This keeps resolveOrCreate
      // usable; it is not equivalent to an uninstall.
      do {
        try FileManager.default.removeItem(at: file)
      } catch {
        throw InstallationIdentityStoreError.unwritable
      }
      return nil
    }
    return id
  }

  private func write(_ id: UUID, to file: URL) throws {
    do {
      try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
      try Self.excludeFromBackup(directory)
      try Data(id.uuidString.lowercased().utf8).write(
        to: file,
        options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication]
      )
      // The atomic write replaces the file, so mark the file itself as well
      // as its directory.
      try Self.excludeFromBackup(file)
    } catch {
      throw InstallationIdentityStoreError.unwritable
    }
  }

  private static func excludeFromBackup(_ url: URL) throws {
    var url = url
    var values = URLResourceValues()
    values.isExcludedFromBackup = true
    try url.setResourceValues(values)
  }
}
