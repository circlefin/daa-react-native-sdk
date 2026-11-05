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

// Signing material for tests that build a `DaaUserClient` directly.
//
// `createDaaUserClient` takes it as a required argument, which is the point:
// the surface cannot be constructed without a credential to sign writes with.
// A read test still has to supply one, so this is what it supplies.
//
// Not a test file — Jest's `testMatch` is `**/__test__/**/*.test.ts`, so this
// module is only ever imported, never collected.

import type { DaaUserSigning } from '../api/signedResource'
import type { OwnerAuthKey } from '../securekey/SecureKey'
import { InMemorySecureKeyStore } from '../testing'

/** The `kid` these tests pin. Any UUID; `authorizeExactRequest` requires one. */
export const TEST_AUTH_KEY_ID = '11111111-1111-4111-8111-111111111111'

/** The Owner these tests resolve an AuthKey for. Any UUID; namespaces the key. */
export const TEST_CLIENT_ENTITY_ID = '00000000-0000-4000-8000-000000000001'

/**
 * Signing for a test that must not sign anything.
 *
 * Resolving throws rather than returning an unusable key, so a read that
 * quietly grew a signature would fail here instead of passing with one nobody
 * asserted on.
 */
export const NO_SIGNING: DaaUserSigning = Object.freeze({
  authKeyId: TEST_AUTH_KEY_ID,
  resolveAuthKey: async (): Promise<OwnerAuthKey> => {
    throw new Error('this test must not resolve the AuthKey')
  },
})

/** An AuthKey the SDK has recorded Circle's registration acknowledgement for. */
export async function registeredAuthKey(): Promise<OwnerAuthKey> {
  const key = await new InMemorySecureKeyStore().resolveOrCreate({
    appId: 'app-123',
    environment: 'sandbox',
    clientEntityId: TEST_CLIENT_ENTITY_ID,
  })
  await key.acknowledgeRegistration()
  return key
}

/** An AuthKey still awaiting that acknowledgement: `resolution()` is `created`. */
export async function unregisteredAuthKey(): Promise<OwnerAuthKey> {
  return new InMemorySecureKeyStore().resolveOrCreate({
    appId: 'app-123',
    environment: 'sandbox',
    clientEntityId: TEST_CLIENT_ENTITY_ID,
  })
}

/** Signing that resolves to a given key, and records how often it was asked. */
export function signingFor(
  authKey: OwnerAuthKey,
  authKeyId: string = TEST_AUTH_KEY_ID,
): DaaUserSigning & { readonly resolutions: () => number } {
  let resolutions = 0
  return {
    authKeyId,
    resolveAuthKey: async () => {
      resolutions += 1
      return authKey
    },
    resolutions: () => resolutions,
  }
}
