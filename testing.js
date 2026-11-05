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

// Legacy-resolver fallback for the package's `./testing` subpath.
//
// Exports-aware resolvers use the `exports` map in package.json
// (-> ./build/testing.js). This stub is for resolvers that ignore `exports`
// (e.g. Metro without `unstable_enablePackageExports` on RN < 0.79), so the
// subpath resolves everywhere.
module.exports = require('./build/testing.js')
