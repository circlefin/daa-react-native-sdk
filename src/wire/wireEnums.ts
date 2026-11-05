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

import type { AccountPurpose, AccountStatus, AccountType, CustodyType } from '../models/Account'
import { unrecognized } from './payload'

// Wire-string to public-type mapping, in one table per type.
//
// One table rather than a `switch` per field, so a wire spelling appears in
// exactly one place and adding a value is one line here plus one arm on the
// public type. The spellings are lower snake_case and none of them matches the
// public `kind` for the multi-word cases, so a mapper written from the type
// instead of the wire would look right and match nothing.
//
// A `Map` rather than an object literal, deliberately: an object literal inherits
// from `Object.prototype`, so `lookup['constructor']` and `lookup['toString']`
// return functions instead of `undefined` and a service value spelled like an
// `Object.prototype` member would be "recognised" as something that is not even a
// custody type. This is a JavaScript hazard with no Kotlin or Swift equivalent,
// and it is pinned by test.

const CUSTODY_TYPES = new Map<string, CustodyType>([
  ['omnibus', Object.freeze({ kind: 'omnibus' })],
  ['segregated', Object.freeze({ kind: 'segregated' })],
  ['self', Object.freeze({ kind: 'self' })],
])

const ACCOUNT_PURPOSES = new Map<string, AccountPurpose>([
  ['custody', Object.freeze({ kind: 'custody' })],
  ['payments', Object.freeze({ kind: 'payments' })],
])

const ACCOUNT_STATUSES = new Map<string, AccountStatus>([
  ['active', Object.freeze({ kind: 'active' })],
  ['pending', Object.freeze({ kind: 'pending' })],
  ['rejected', Object.freeze({ kind: 'rejected' })],
  ['archived', Object.freeze({ kind: 'archived' })],
])

const ACCOUNT_TYPES = new Map<string, AccountType>([
  ['first_party', Object.freeze({ kind: 'first_party' })],
  ['third_party', Object.freeze({ kind: 'third_party' })],
])

export function toCustodyType(raw: string | null): CustodyType {
  return (raw === null ? undefined : CUSTODY_TYPES.get(raw)) ?? unrecognized(raw)
}

export function toAccountPurpose(raw: string | null): AccountPurpose {
  return (raw === null ? undefined : ACCOUNT_PURPOSES.get(raw)) ?? unrecognized(raw)
}

export function toAccountStatus(raw: string | null): AccountStatus {
  return (raw === null ? undefined : ACCOUNT_STATUSES.get(raw)) ?? unrecognized(raw)
}

export function toAccountType(raw: string | null): AccountType {
  return (raw === null ? undefined : ACCOUNT_TYPES.get(raw)) ?? unrecognized(raw)
}
