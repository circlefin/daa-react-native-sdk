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

import { Account } from '../models/Account'
import { Address, BusinessPii } from '../models/BusinessPii'
import { toMoney } from './moneyPayload'
import {
  asObject,
  MalformedPayloadError,
  optionalObject,
  optionalString,
  requiredString,
} from './payload'
import { toAccountPurpose, toAccountStatus, toAccountType, toCustodyType } from './wireEnums'

export { MalformedPayloadError } from './payload'

function requiredArray(payload: Record<string, unknown>, name: string): unknown[] {
  const value = payload[name]
  if (!Array.isArray(value)) {
    throw new MalformedPayloadError(name)
  }
  return value
}

function toAddress(payload: Record<string, unknown>): Address {
  return new Address({
    city: optionalString(payload, 'city'),
    country: optionalString(payload, 'country'),
    district: optionalString(payload, 'district'),
    line1: optionalString(payload, 'line1'),
    line2: optionalString(payload, 'line2'),
    postalCode: optionalString(payload, 'postalCode'),
  })
}

function toBusinessPii(payload: Record<string, unknown>): BusinessPii {
  const address = optionalObject(payload, 'address')
  return new BusinessPii({
    address: address === null ? null : toAddress(address),
    businessName: optionalString(payload, 'businessName'),
    businessUniqueIdentifier: optionalString(payload, 'businessUniqueIdentifier'),
    identifierIssuingCountryCode: optionalString(payload, 'identifierIssuingCountryCode'),
  })
}

/**
 * Map a decoded `Account` payload onto the public model.
 *
 * Unknown *additional* fields are ignored and an unfamiliar *present* closed-set
 * value degrades to `unrecognized`; a missing guaranteed field throws. That is the
 * line between forward compatibility and accepting a hole.
 *
 * `depositAddress` and `businessPii` are read because the service's responses
 * carry them: self-custody and segregated accounts add `blockchain` and
 * `depositAddress`. The OpenAPI schema shows none of the three, so the decoder
 * follows the service's responses. For a self-custody consumer,
 * `depositAddress` is the field the account exists for.
 *
 * @throws MalformedPayloadError
 */
export function toAccount(value: unknown): Account {
  const payload = asObject(value, 'account')
  const businessPii = optionalObject(payload, 'businessPii')

  return new Account({
    accountId: requiredString(payload, 'accountId'),
    balances: requiredArray(payload, 'balances').map((balance) => toMoney(balance, 'balances[]')),
    blockchain: optionalString(payload, 'blockchain'),
    businessPii: businessPii === null ? null : toBusinessPii(businessPii),
    clientEntityId: optionalString(payload, 'clientEntityId'),
    // Outside the guaranteed set, unlike the three below, so an absent one is
    // tolerated and is the only way to reach `unrecognized` with a null raw
    // value.
    custodyType: toCustodyType(optionalString(payload, 'custodyType')),
    depositAddress: optionalString(payload, 'depositAddress'),
    description: optionalString(payload, 'description'),
    entityId: requiredString(payload, 'entityId'),
    groupId: optionalString(payload, 'groupId'),
    // Guaranteed, so an absent one is malformed. Only an unfamiliar *present*
    // value becomes `unrecognized`.
    purpose: toAccountPurpose(requiredString(payload, 'purpose')),
    status: toAccountStatus(requiredString(payload, 'status')),
    type: toAccountType(requiredString(payload, 'type')),
  })
}

export function toAccounts(value: unknown): readonly Account[] {
  if (!Array.isArray(value)) {
    throw new MalformedPayloadError('accounts')
  }
  return Object.freeze(value.map(toAccount))
}
