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

import { AddressObject } from '../models/AddressObject'
import { MalformedPayloadError, asObject, optionalString, requiredString } from './payload'

/**
 * Map a decoded `AddressObject` payload onto the public model.
 *
 * `id`, `address`, and `chain` are guaranteed by every custody source a
 * by-id read can return from; `addressTag`, `currency`, and `accountId` are
 * not — see the class note on `AddressObject` for the source-by-source
 * evidence, which disagrees with the schema (it names only `addressTag` as
 * nullable).
 *
 * Unknown *additional* fields are ignored, matching the service's own
 * tolerance for unknown fields — see `addressObjectPayload.test.ts`'s
 * forward-compatibility case.
 *
 * `currency` and `chain` are carried as plain strings rather than a
 * closed-set union: the service adds chains and currencies independently of an
 * SDK release, the same reasoning `models/Account.ts` and `models/Money.ts`
 * give for `Account.blockchain` and `Money.currency`. Neither needs the
 * `wireEnums.ts`-style unrecognized-with-raw-value treatment `custodyType`,
 * `purpose`, `status`, and `type` need, because neither is modelled as a
 * small closed set this SDK discriminates on.
 *
 * @throws MalformedPayloadError
 */
export function toAddressObject(value: unknown): AddressObject {
  const payload = asObject(value, 'addressObject')

  return new AddressObject({
    id: requiredString(payload, 'id'),
    address: requiredString(payload, 'address'),
    addressTag: optionalString(payload, 'addressTag'),
    currency: optionalString(payload, 'currency'),
    chain: requiredString(payload, 'chain'),
    accountId: optionalString(payload, 'accountId'),
  })
}

/** Decode the `data` array returned by the deposit-address collection. */
export function toAddressObjects(value: unknown): readonly AddressObject[] {
  if (!Array.isArray(value)) {
    throw new MalformedPayloadError('depositAddresses')
  }
  return Object.freeze(value.map(toAddressObject))
}
