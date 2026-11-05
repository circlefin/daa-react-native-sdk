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

import type { TransferTypeInfo, WireInstructionBeneficiary } from '../models/Wire'
import { Wire, WireInstruction, WireInstructionBeneficiaryBank, WireSummary } from '../models/Wire'
import {
  optionalBankAddress,
  optionalBoolean,
  requiredBillingDetails,
  toFiatAccountStatus,
} from './fiatAccountPayload'
import {
  MalformedPayloadError,
  asObject,
  optionalObject,
  optionalString,
  requiredString,
} from './payload'

function toWireInstructionBeneficiary(
  payload: Record<string, unknown>,
): WireInstructionBeneficiary {
  return Object.freeze({
    name: optionalString(payload, 'name', 'beneficiary.name'),
    address1: optionalString(payload, 'address1', 'beneficiary.address1'),
    address2: optionalString(payload, 'address2', 'beneficiary.address2'),
  })
}

function toWireInstructionBeneficiaryBank(
  payload: Record<string, unknown>,
): WireInstructionBeneficiaryBank {
  return new WireInstructionBeneficiaryBank({
    name: optionalString(payload, 'name', 'beneficiaryBank.name'),
    swiftCode: optionalString(payload, 'swiftCode', 'beneficiaryBank.swiftCode'),
    routingNumber: optionalString(payload, 'routingNumber', 'beneficiaryBank.routingNumber'),
    accountNumber: optionalString(payload, 'accountNumber', 'beneficiaryBank.accountNumber'),
    currency: optionalString(payload, 'currency', 'beneficiaryBank.currency'),
    address: optionalString(payload, 'address', 'beneficiaryBank.address'),
    city: optionalString(payload, 'city', 'beneficiaryBank.city'),
    postalCode: optionalString(payload, 'postalCode', 'beneficiaryBank.postalCode'),
    country: optionalString(payload, 'country', 'beneficiaryBank.country'),
  })
}

/**
 * A `transferTypesInfo` entry the service does not describe is ignored rather
 * than rejected — the SDK does not act on this field, only relays it, and a
 * relayed field gets that tolerance throughout.
 */
function toTransferTypeInfo(value: unknown, label: string): TransferTypeInfo | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return null
  }
  const payload = value as Record<string, unknown>
  const currencies = payload.currencies
  if (!Array.isArray(currencies) || !currencies.every((entry) => typeof entry === 'string')) {
    throw new MalformedPayloadError(`${label}.currencies`)
  }
  return Object.freeze({ currencies: Object.freeze(currencies.slice()) })
}

function toTransferTypesInfo(
  payload: Record<string, unknown>,
): Readonly<Record<string, TransferTypeInfo>> | null {
  const value = payload.transferTypesInfo
  if (value === undefined || value === null) {
    return null
  }
  if (typeof value !== 'object' || Array.isArray(value)) {
    throw new MalformedPayloadError('transferTypesInfo')
  }
  const result = Object.create(null) as Record<string, TransferTypeInfo>
  for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
    const info = toTransferTypeInfo(entry, `transferTypesInfo.${key}`)
    if (info !== null) {
      result[key] = info
    }
  }
  return Object.freeze(result)
}

/** Decode one `WireSummary` (`GET /v1/banks/wires` collection entry). */
export function toWireSummary(value: unknown): WireSummary {
  const payload = asObject(value, 'wire')
  return new WireSummary({
    id: requiredString(payload, 'id'),
    type: optionalString(payload, 'type'),
    status: toFiatAccountStatus(requiredString(payload, 'status')),
    description: requiredString(payload, 'description'),
    trackingRef: requiredString(payload, 'trackingRef'),
    fingerprint: requiredString(payload, 'fingerprint'),
    billingDetails: requiredBillingDetails(payload, 'billingDetails'),
    bankAddress: optionalBankAddress(payload, 'bankAddress'),
    virtualAccountEnabled: optionalBoolean(payload, 'virtualAccountEnabled'),
    ffcMemo: optionalString(payload, 'ffcMemo'),
    createDate: requiredString(payload, 'createDate'),
    updateDate: requiredString(payload, 'updateDate'),
  })
}

/** Decode the wire collection's unpaginated `data` array. */
export function toWireSummaries(value: unknown): readonly WireSummary[] {
  if (!Array.isArray(value)) {
    throw new MalformedPayloadError('wires')
  }
  return Object.freeze(value.map(toWireSummary))
}

/** Decode one `Wire` (`GET /v1/banks/wires/{id}`). */
export function toWire(value: unknown): Wire {
  const payload = asObject(value, 'wire')
  return new Wire({
    id: requiredString(payload, 'id'),
    type: optionalString(payload, 'type'),
    status: toFiatAccountStatus(requiredString(payload, 'status')),
    description: requiredString(payload, 'description'),
    trackingRef: requiredString(payload, 'trackingRef'),
    fingerprint: requiredString(payload, 'fingerprint'),
    billingDetails: requiredBillingDetails(payload, 'billingDetails'),
    bankAddress: optionalBankAddress(payload, 'bankAddress'),
    virtualAccountEnabled: optionalBoolean(payload, 'virtualAccountEnabled'),
    ffcMemo: optionalString(payload, 'ffcMemo'),
    transferTypesInfo: toTransferTypesInfo(payload),
    createDate: requiredString(payload, 'createDate'),
    updateDate: requiredString(payload, 'updateDate'),
  })
}

/**
 * Decode a `WireInstruction` (`GET /v1/banks/wires/{id}/instructions`). Every
 * field is optional in the service's own schema.
 */
export function toWireInstruction(value: unknown): WireInstruction {
  const payload = asObject(value, 'wireInstruction')
  const beneficiary = optionalObject(payload, 'beneficiary')
  const beneficiaryBank = optionalObject(payload, 'beneficiaryBank')
  return new WireInstruction({
    trackingRef: optionalString(payload, 'trackingRef'),
    beneficiary: beneficiary === null ? null : toWireInstructionBeneficiary(beneficiary),
    beneficiaryBank:
      beneficiaryBank === null ? null : toWireInstructionBeneficiaryBank(beneficiaryBank),
    virtualAccountEnabled: optionalBoolean(payload, 'virtualAccountEnabled'),
  })
}
