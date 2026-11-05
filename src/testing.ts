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

// Test-only entry point: the package's `./testing` subpath.
//
// Exposes the DAA Owner-key interfaces and a WebCrypto-backed in-memory store so
// consumers and golden vectors can exercise signing WITHOUT device hardware.
//
// NOT for production: the in-memory store holds a P-256 private key in process
// memory. It fails closed when constructed in a production build.
//
// The Owner-key interfaces (OwnerAuthKey / OwnerKeyIdentity / SecureKeyStore)
// are exported from the main entry (`.`) since they are the contract a
// production/native store implements. This subpath adds only the concrete
// test double.

export { InMemorySecureKeyStore } from './securekey/InMemorySecureKey'
