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

import type { DaaTransport } from '../transport/DaaTransport'
import { AchFiatAccountsClient } from './AchFiatAccountsClient'
import { WireFiatAccountsClient } from './WireFiatAccountsClient'

/**
 * Reads over both fiat-account rails, as the SDK contract's
 * `FiatAccountsClient`: `{ wires: WireFiatAccountsClient; ach:
 * AchFiatAccountsClient }`.
 *
 * A thin composing wrapper, the same role `DaaUserClient` itself plays one
 * level up: neither rail needs the other's state, and the SDK contract does
 * not expose a rail selector — wire and ACH use distinct rail-specific
 * collection paths — so nothing is shared here beyond the transport
 * both sub-clients are constructed with.
 *
 * Not constructible by a consumer: exported from `index.ts` as a type only,
 * and `WireFiatAccountsClient`/`AchFiatAccountsClient`'s own `#transport`
 * fields make each nominal.
 */
export class FiatAccountsClient {
  /** Reads over wire fiat accounts. */
  readonly wires: WireFiatAccountsClient
  /** Reads over ACH fiat accounts. */
  readonly ach: AchFiatAccountsClient

  /** @internal Constructed only through `createDaaUserClient`. */
  constructor(transport: DaaTransport) {
    this.wires = new WireFiatAccountsClient(transport)
    this.ach = new AchFiatAccountsClient(transport)
    Object.freeze(this)
  }
}
