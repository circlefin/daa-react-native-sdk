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
import java.io.File
import java.util.UUID

// Durable per-install UUID for DaaAuthKeyIdentity.installationId.
// Native docs: the caller persists the UUID; a new install gets a new UUID.
// App-private no-backup storage is wiped on uninstall, so a reinstall mints a
// new UUID and therefore a new Keystore AuthKey.

internal object InstallationIdentityStore {
    private const val FILE_NAME = "daa-installation-id"
    private val lock = Any()

    fun loadOrCreate(context: Context): UUID {
        // One tmp path for all writers. Serialize so a first-run race cannot
        // persist id_B after a caller already returned id_A (two Keystore
        // aliases). iOS gets the same exclusivity from its actor / SecItemAdd.
        synchronized(lock) {
            val dir = context.noBackupFilesDir
            val file = File(dir, FILE_NAME)
            readUuid(file)?.let {
                return it
            }

            val id = UUID.randomUUID()
            val tmp = File(dir, "$FILE_NAME.tmp")
            tmp.writeText(id.toString().lowercase())
            if (!tmp.renameTo(file)) {
                tmp.delete()
                readUuid(file)?.let {
                    return it
                }
                throw ContractViolationException()
            }
            return readUuid(file) ?: id
        }
    }

    // Truncated or garbage files are wiped so the next mint is a new UUID.
    // That does NOT uninstall: the previous Keystore key remains under the
    // old alias, still registered with Circle if enrollment happened, never
    // revoked. The SDK silently creates a new AuthKey. This keeps
    // resolveOrCreate usable; it is not equivalent to wiping app data.
    private fun readUuid(file: File): UUID? {
        if (!file.exists()) {
            return null
        }
        val parsed = runCatching { UUID.fromString(file.readText().trim()) }.getOrNull()
        if (parsed == null) {
            file.delete()
            return null
        }
        return parsed
    }
}
