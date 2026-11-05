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

// Host-side tests for InstallationIdentityStore, built with swiftc on macOS
// outside the pod (`yarn test:ios-native`, or
// `xcrun swiftc ios/InstallationIdentityStore.swift ios/Tests/main.swift`
// and run the output). Not part of the pod or the npm package: the store
// has no ExpoModulesCore or DaaSdk dependency. Uninstall/reinstall itself
// can only be checked on a device.

import Foundation

var failures = 0

func check(_ condition: @autoclosure () -> Bool, _ message: String, line: Int = #line) {
  if !condition() {
    failures += 1
    print("FAIL (line \(line)): \(message)")
  }
}

func freshDirectory() -> URL {
  FileManager.default.temporaryDirectory
    .appendingPathComponent("installation-identity-tests-\(UUID().uuidString)", isDirectory: true)
}

func fileURL(_ directory: URL) -> URL {
  directory.appendingPathComponent(InstallationIdentityStore.fileName)
}

func contents(_ directory: URL) -> String? {
  try? String(contentsOf: fileURL(directory), encoding: .utf8)
}

func test(_ name: String, _ body: () throws -> Void) {
  do {
    try body()
    print("ok - \(name)")
  } catch {
    failures += 1
    print("FAIL: \(name) threw \(error)")
  }
}

test("new install mints a UUID and persists it, excluded from backup") {
  let directory = freshDirectory()
  let store = InstallationIdentityStore(directory: directory)
  let id = try store.loadOrCreate()
  check(contents(directory) == id.uuidString.lowercased(), "file holds the minted UUID")
  let excluded = try fileURL(directory).resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup
  check(excluded == true, "file is excluded from backup")
  let directoryExcluded = try directory.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup
  check(directoryExcluded == true, "directory is excluded from backup")
}

test("load returns the persisted UUID on later runs") {
  let directory = freshDirectory()
  let first = try InstallationIdentityStore(directory: directory).loadOrCreate()
  let second = try InstallationIdentityStore(directory: directory).loadOrCreate()
  check(first == second, "same UUID across store instances (app update / restart)")
}

test("an emptied container (reinstall) mints a new UUID") {
  let directory = freshDirectory()
  let first = try InstallationIdentityStore(directory: directory).loadOrCreate()
  try FileManager.default.removeItem(at: directory)
  let second = try InstallationIdentityStore(directory: directory).loadOrCreate()
  check(first != second, "reinstall gets a different UUID")
}

test("a malformed file is replaced by a new UUID") {
  let directory = freshDirectory()
  try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
  try Data("not-a-uuid".utf8).write(to: fileURL(directory))
  let id = try InstallationIdentityStore(directory: directory).loadOrCreate()
  check(contents(directory) == id.uuidString.lowercased(), "file rewritten with the new UUID")
}

test("an unreadable file throws and is left in place") {
  let directory = freshDirectory()
  try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
  // A directory at the file's path cannot be read as data.
  try FileManager.default.createDirectory(at: fileURL(directory), withIntermediateDirectories: true)
  var thrown: Error?
  do {
    _ = try InstallationIdentityStore(directory: directory).loadOrCreate()
  } catch {
    thrown = error
  }
  check((thrown as? InstallationIdentityStoreError) == .unreadable, "throws unreadable")
  check(FileManager.default.fileExists(atPath: fileURL(directory).path), "not removed")
}

test("concurrent first runs agree on one UUID") {
  let directory = freshDirectory()
  let resultsLock = NSLock()
  var results: [UUID?] = []
  DispatchQueue.concurrentPerform(iterations: 16) { _ in
    let id = try? InstallationIdentityStore(directory: directory).loadOrCreate()
    resultsLock.lock()
    results.append(id)
    resultsLock.unlock()
  }
  check(results.count == 16 && Set(results).count == 1 && results[0] != nil, "all callers got the same UUID")
}

if failures > 0 {
  print("\(failures) failure(s)")
  exit(1)
}
print("all passed")
