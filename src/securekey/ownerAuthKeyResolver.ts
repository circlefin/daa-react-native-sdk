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

// Resolving the installation AuthKey by alias, in one place.
//
// Two call sites need the same key: the login ceremony selects it after Social
// Session (`AuthClient`), and the authenticated operations surface signs writes
// with it (`DaaClient.forUser`). The key is not carried on `DaaUserContext` —
// that context is a decoded server result, not a handle to enclave-held key
// material — so `forUser` re-resolves by the same `{appId, environment}` alias
// login used, together with the SAME context's `clientEntityId`.
// `DeviceContext.authKeyId` supplies the JWS `kid` alongside it.
//
// The lazy `NativeSecureKeyStore` is why this is a factory rather than a free
// function. Constructing the store requires the Expo `DaaSecureKey` module, and
// `DaaClient` construction deliberately does not; the store is therefore built
// on first resolution and then reused, so login and every later signed write
// share one store — and so share its in-flight `resolveOrCreate` map rather
// than racing two independent handles for the same alias.

import { contractViolation } from '../errors'
import { NativeSecureKeyStore } from './NativeSecureKey'
import { resolveNativeBridge } from './resolveNativeBridge'
import type { AppKeyIdentity, OwnerAuthKey, SecureKeyStore } from './SecureKey'

/**
 * Resolves the installation AuthKey for one already-known Owner.
 *
 * Deliberately a zero-arg function rather than the store itself: a holder can
 * obtain the one key its identity namespaces and nothing else — no alias of
 * its choosing, and no store to resolve a different one from. This is the
 * shape `DaaUserSigning.resolveAuthKey` (`api/signedResource.ts`) needs,
 * because by the time `forUser` builds one it already knows which Owner it is
 * signing for. It is NOT the shape {@link createOwnerAuthKeyResolver} returns
 * — see {@link AppAuthKeyResolver}.
 */
export type OwnerAuthKeyResolver = () => Promise<OwnerAuthKey>

/**
 * Resolves the installation AuthKey for a given Owner, by `clientEntityId`.
 *
 * `clientEntityId` is a per-call parameter rather than baked into the
 * resolver at construction: it is not known when `DaaClient`
 * builds this resolver (only the Social Session response names an Owner), and
 * one long-lived `DaaClient` may serve more than one Owner over its lifetime
 * — sign-out, then sign back in as someone else. Each call site binds the
 * `clientEntityId` it already has (Social Session's response for login;
 * `DaaUserContext.clientEntityId` for `forUser`) and, for `forUser`, wraps the
 * result down to an {@link OwnerAuthKeyResolver} before handing it to a
 * resource client — a resource client has no Owner concept of its own.
 */
export type AppAuthKeyResolver = (clientEntityId: string) => Promise<OwnerAuthKey>

/**
 * Build the resolver for one application identity.
 *
 * @param identity App-level identity (`appId`, `environment`); `null` when
 *   the SDK has no application identity to select a key with, which fails
 *   closed at the first resolution rather than at construction —
 *   `AuthClient` is built for Prepare, and Prepare never touches an
 *   AuthKey.
 * @param secureKeys Injected store, which tests substitute. Absent, the native
 *   store is constructed on first use and reused.
 */
export function createOwnerAuthKeyResolver(
  identity: AppKeyIdentity | null,
  secureKeys: SecureKeyStore | null,
): AppAuthKeyResolver {
  // The mutable slot the lazily-constructed native store fills. A closure
  // variable rather than a field because the clients holding this resolver are
  // sealed with `Object.freeze`.
  let nativeStore: NativeSecureKeyStore | null = null

  return async (clientEntityId: string) => {
    if (identity === null) {
      throw contractViolation('AuthKey selection requires the DaaClient application identity')
    }
    const store = secureKeys ?? (nativeStore ??= new NativeSecureKeyStore(resolveNativeBridge()))
    return store.resolveOrCreate({ ...identity, clientEntityId })
  }
}
