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

/**
 * Chain names recognized at author time, mirrored from the public Accounts
 * API reference's `chain` enum for deposit-address generation, for editor
 * autocomplete and typo protection only.
 *
 * This is **not** a runtime allowlist. That enum is a server-owned,
 * externally-growing catalog — Circle onboards new blockchains on its own
 * release cadence, and each onboarding is a doc/contract update on that side,
 * not a business-vocabulary change on this one. A closed local allowlist would
 * make every already-published SDK version reject a newly onboarded chain with
 * `contract_violation` before the request ever reaches the network, until a
 * new SDK release reaches every integrator through mobile app-store review —
 * a multi-week gap in the worst case. `DepositAddressesClient.create` therefore
 * only checks that a supplied `chain` is a plausible non-empty string and lets
 * the server be the sole authority (it 400s on a genuinely invalid value).
 */
export const DEPOSIT_ADDRESS_CHAINS = Object.freeze([
  'ALGO',
  'APTOS',
  'ARB',
  'AVAX',
  'BASE',
  'BTC',
  'CELO',
  'CODEX',
  'ETH',
  'HBAR',
  'HYPEREVM',
  'INK',
  'LINEA',
  'NEAR',
  'NOBLE',
  'OP',
  'PAH',
  'PLUME',
  'POLY',
  'SEI',
  'SOL',
  'SONIC',
  'SUI',
  'UNI',
  'WORLDCHAIN',
  'XDC',
  'XLM',
  'XRP',
  'ZKS',
  'ZKSYNC',
] as const)

export type DepositAddressChain = (typeof DEPOSIT_ADDRESS_CHAINS)[number]

/**
 * Body for creating or resolving a deposit address.
 *
 * This SDK's typed client only supports account-scoped requests: `accountId` is
 * always required. DAA derives custody from the supplied `accountId`, so any
 * account the caller names is reachable, an omnibus account included. The
 * broader public Accounts API additionally permits omitting `accountId` to
 * select the caller's omnibus master account. That omission is deliberately
 * not exposed here: this SDK's operations are bound to an authenticated
 * device/Owner context, and a caller who forgot `accountId` would silently get
 * the master account's address rather than their own.
 *
 * `chain` is optional: per the service's `GenerateAddressRequest` contract, it
 * is required for an omnibus `accountId`, where DAA creates the address, and
 * optional for segregated/self-custody accounts, where an omitted `chain`
 * resolves to the account's immutable home blockchain. An omnibus request
 * without `chain` is the service's to reject, not this SDK's.
 */
export type GenerateAddressRequest = Readonly<{
  /** Caller-generated UUID v4, durably reused for retries of this operation. */
  idempotencyKey: string
  /** The account to create or resolve a deposit address for. */
  accountId: string
  /** Currency accepted by the public Accounts request contract. */
  currency: 'USD' | 'EUR'
  /**
   * Blockchain to generate the address on. Optional — when omitted, resolves
   * to the account's immutable home blockchain. See {@link DEPOSIT_ADDRESS_CHAINS}
   * for why an unrecognized value is not rejected locally.
   */
  chain?: DepositAddressChain
}>
