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

import { ACH, ACHInstruction, ACHInstructionBeneficiaryBank } from '../models/Ach'
import type { ACHInstructionBeneficiary } from '../models/Ach'
import {
  optionalBankAddress,
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

// See `models/Ach.ts`'s file header: this decoder mirrors `wirePayload.ts`
// field-for-field wherever `Wire`/`WireInstruction` and `ACH`/`ACHInstruction`
// share a shape, and the model file explains the one extra field
// (`ACH.routingNumber`).

function toAchInstructionBeneficiary(payload: Record<string, unknown>): ACHInstructionBeneficiary {
  return Object.freeze({
    name: optionalString(payload, 'name', 'beneficiary.name'),
    address1: optionalString(payload, 'address1', 'beneficiary.address1'),
    address2: optionalString(payload, 'address2', 'beneficiary.address2'),
  })
}

function toAchInstructionBeneficiaryBank(
  payload: Record<string, unknown>,
): ACHInstructionBeneficiaryBank {
  return new ACHInstructionBeneficiaryBank({
    name: optionalString(payload, 'name', 'beneficiaryBank.name'),
    routingNumber: optionalString(payload, 'routingNumber', 'beneficiaryBank.routingNumber'),
    accountNumber: optionalString(payload, 'accountNumber', 'beneficiaryBank.accountNumber'),
    address: optionalString(payload, 'address', 'beneficiaryBank.address'),
    city: optionalString(payload, 'city', 'beneficiaryBank.city'),
    postalCode: optionalString(payload, 'postalCode', 'beneficiaryBank.postalCode'),
    country: optionalString(payload, 'country', 'beneficiaryBank.country'),
  })
}

/** Decode one `ACH` fiat account, for both list entries and the by-id read. */
export function toAch(value: unknown): ACH {
  const payload = asObject(value, 'ach')
  return new ACH({
    id: requiredString(payload, 'id'),
    type: optionalString(payload, 'type'),
    status: toFiatAccountStatus(requiredString(payload, 'status')),
    description: requiredString(payload, 'description'),
    trackingRef: requiredString(payload, 'trackingRef'),
    fingerprint: requiredString(payload, 'fingerprint'),
    billingDetails: requiredBillingDetails(payload, 'billingDetails'),
    bankAddress: optionalBankAddress(payload, 'bankAddress'),
    routingNumber: optionalString(payload, 'routingNumber'),
    createDate: requiredString(payload, 'createDate'),
    updateDate: requiredString(payload, 'updateDate'),
  })
}

/** Decode the ACH collection's unpaginated `data` array. */
export function toAchList(value: unknown): readonly ACH[] {
  if (!Array.isArray(value)) {
    throw new MalformedPayloadError('ach')
  }
  return Object.freeze(value.map(toAch))
}

/** Decode an `ACHInstruction` (`GET /v1/banks/ach/{id}/instructions`). */
export function toAchInstruction(value: unknown): ACHInstruction {
  const payload = asObject(value, 'achInstruction')
  const beneficiary = optionalObject(payload, 'beneficiary')
  const beneficiaryBank = optionalObject(payload, 'beneficiaryBank')
  return new ACHInstruction({
    trackingRef: optionalString(payload, 'trackingRef'),
    beneficiary: beneficiary === null ? null : toAchInstructionBeneficiary(beneficiary),
    beneficiaryBank:
      beneficiaryBank === null ? null : toAchInstructionBeneficiaryBank(beneficiaryBank),
  })
}
